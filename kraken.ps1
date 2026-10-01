#requires -Version 7.0
<#
Kraken order-management CLI. Dry-run is the default; --live requires CONFIRM.
Usage: pwsh -File ./kraken.ps1 <command> [arguments]
#>

$ErrorActionPreference = 'Stop'
$script:Root = $PSScriptRoot
$script:AccountFile = Join-Path $script:Root 'accounts.json'
$script:LogFile = Join-Path $script:Root 'logs/trade_log.jsonl'
$script:AllowedKeys = @('label', 'pair', 'type', 'ordertype', 'price', 'price2', 'volume', 'displayvol', 'oflags', 'trigger', 'timeinforce')
$script:RequiredKeys = @('pair', 'type', 'ordertype', 'volume')
$script:PriceRules = @{
    market = @{ required = @(); forbidden = @('price', 'price2') }
    limit = @{ required = @('price'); forbidden = @('price2') }
    'stop-loss' = @{ required = @('price'); forbidden = @('price2') }
    'take-profit' = @{ required = @('price'); forbidden = @('price2') }
    'trailing-stop' = @{ required = @('price'); forbidden = @('price2') }
    'stop-loss-limit' = @{ required = @('price', 'price2'); forbidden = @() }
    'take-profit-limit' = @{ required = @('price', 'price2'); forbidden = @() }
    'trailing-stop-limit' = @{ required = @('price', 'price2'); forbidden = @() }
}
$script:Invariant = [Globalization.CultureInfo]::InvariantCulture
$script:OriginalArgs = @($args)
$script:LastNonce = [long]0

function Fail([string]$Message) { throw "ABORTED: $Message" }
function Dec($Value) { return [decimal]::Parse([string]$Value, [Globalization.NumberStyles]::Float, $script:Invariant) }
function DStr([decimal]$Value) { return $Value.ToString('0.############################', $script:Invariant) }
function UtcNow { return [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', $script:Invariant) }
function Prop($Object, [string]$Name, $Default = $null) {
    if ($null -ne $Object -and $Object.Contains($Name)) { return $Object[$Name] }
    return $Default
}

function Read-Json([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { Fail "File not found: $Path" }
    try { return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable }
    catch { Fail "Invalid JSON in ${Path}: $_" }
}

function Account([string]$Name) {
    if (-not $Name) { Fail '--account is required' }
    $accounts = (Read-Json $script:AccountFile)['accounts']
    if (-not $accounts.Contains($Name)) { Fail "Unknown account '$Name'. Valid accounts: $(@($accounts.Keys | Sort-Object) -join ', ')" }
    $config = $accounts[$Name]
    $envFile = Join-Path $script:Root '.env'
    $values = @{}
    if (Test-Path -LiteralPath $envFile) {
        foreach ($line in [IO.File]::ReadAllLines($envFile)) {
            if ($line -match '^\s*(?:export\s+)?([A-Za-z_][A-Za-z_0-9]*)\s*=\s*(.*?)\s*$') {
                $values[$Matches[1]] = $Matches[2].Trim().Trim('"', "'")
            }
        }
    }
    $key = [Environment]::GetEnvironmentVariable($config['key_env'])
    $secret = [Environment]::GetEnvironmentVariable($config['secret_env'])
    if (-not $key) { $key = $values[$config['key_env']] }
    if (-not $secret) { $secret = $values[$config['secret_env']] }
    if (-not $key -or -not $secret) {
        Fail "Account '$Name' needs $($config['key_env']) and $($config['secret_env']) set in .env"
    }
    Write-Host "Account: $Name - $(Prop $config 'description' '')`n"
    return @{ key = $key; secret = $secret }
}

function Form-Encode($Fields) {
    return (@(foreach ($entry in $Fields.GetEnumerator()) {
        '{0}={1}' -f [uri]::EscapeDataString([string]$entry.Key), [uri]::EscapeDataString([string]$entry.Value)
    }) -join '&')
}

function Api([string]$Endpoint, $Params = @{}, $Credentials = $null) {
    $privateCall = $null -ne $Credentials
    $path = if ($privateCall) { "/0/private/$Endpoint" } else { "/0/public/$Endpoint" }
    $fields = [ordered]@{}
    if ($privateCall) {
        $script:LastNonce = [Math]::Max([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(), $script:LastNonce + 1)
        $fields['nonce'] = [string]$script:LastNonce
    }
    foreach ($key in $Params.Keys) { $fields[$key] = $Params[$key] }
    $body = Form-Encode $fields
    $headers = @{}
    if ($privateCall) {
        $headers['API-Key'] = $Credentials.key
        $sha = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($fields['nonce'] + $body))
        $pathBytes = [Text.Encoding]::UTF8.GetBytes($path)
        $payload = [byte[]]::new($pathBytes.Length + $sha.Length)
        [Array]::Copy($pathBytes, 0, $payload, 0, $pathBytes.Length)
        [Array]::Copy($sha, 0, $payload, $pathBytes.Length, $sha.Length)
        $hmac = [Security.Cryptography.HMACSHA512]::new([Convert]::FromBase64String($Credentials.secret))
        try { $headers['API-Sign'] = [Convert]::ToBase64String($hmac.ComputeHash($payload)) }
        finally { $hmac.Dispose() }
    }
    if ($privateCall) {
        $response = Invoke-RestMethod -Uri "https://api.kraken.com$path" -Method Post -Headers $headers -Body $body -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 30
    } else {
        $uri = "https://api.kraken.com$path"
        if ($body) { $uri += "?$body" }
        $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 30
    }
    return $response | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable
}

function Check-Response($Response, [string]$Endpoint) {
    if (@($Response['error']).Count -gt 0) { Fail "Kraken $Endpoint returned error: $($Response['error'] -join ', ')" }
}

function Pair-Info($Pairs) {
    $response = Api 'AssetPairs' @{ pair = $Pairs -join ',' }
    Check-Response $response 'AssetPairs'
    $results = @($response['result'].Values)
    $found = @{}
    foreach ($pair in $Pairs) {
        $match = $null
        foreach ($info in $results) {
            if ($pair -ceq (Prop $info 'altname' '') -or $pair -ceq ([string](Prop $info 'wsname' '')).Replace('/', '')) { $match = $info; break }
        }
        if ($null -eq $match -and $Pairs.Count -eq 1 -and $results.Count -eq 1) { $match = $results[0] }
        if ($null -eq $match) { Fail "Pair '$pair' not found in AssetPairs response" }
        $found[$pair] = $match
    }
    return $found
}

function Print-Orders($Orders) {
    if (-not $Orders -or $Orders.Count -eq 0) { Write-Host '(none)'; return }
    Write-Host ('{0,-22} {1,-10} {2,-5} {3,-20} {4,14} {5,18} {6,18} {7,-8}' -f 'TxID','Pair','Type','Ordertype','Price','Volume','Filled','Status')
    Write-Host ('-' * 122)
    foreach ($txid in $Orders.Keys) {
        $order = $Orders[$txid]; $descr = Prop $order 'descr' @{}
        Write-Host ('{0,-22} {1,-10} {2,-5} {3,-20} {4,14} {5,18} {6,18} {7,-8}' -f $txid,(Prop $descr 'pair' ''),(Prop $descr 'type' ''),(Prop $descr 'ordertype' ''),(Prop $descr 'price' ''),(Prop $order 'vol' ''),(Prop $order 'vol_exec' ''),(Prop $order 'status' 'open'))
    }
}

function Load-Order([string]$Path, [string]$AccountName) {
    $doc = Read-Json $Path
    if ($doc['account'] -cne $AccountName) { Fail "Account mismatch: order file says '$($doc['account'])' but --account is '$AccountName'" }
    $orders = $doc['orders']
    if ($orders -isnot [array] -or $orders.Count -eq 0) { Fail "Order file has no 'orders' list" }
    $index = 0
    foreach ($order in $orders) {
        $index++
        if ($order -isnot [System.Collections.IDictionary]) { Fail "order $index must be an object" }
        $label = Prop $order 'label' "order $index"
        foreach ($key in $order.Keys) {
            if ($key -cnotin $script:AllowedKeys) { Fail "${label}: unknown key '$key'" }
            if ($order[$key] -isnot [string]) { Fail "${label}: value for '$key' must be a quoted string" }
        }
        foreach ($key in $script:RequiredKeys) { if (-not $order.Contains($key)) { Fail "${label}: missing required key '$key'" } }
        if ($order['type'] -cnotin @('buy','sell')) { Fail "${label}: type must be 'buy' or 'sell'" }
        $orderType = $order['ordertype']
        if (-not $script:PriceRules.ContainsKey($orderType)) { Fail "${label}: unsupported ordertype '$orderType'" }
        foreach ($key in $script:PriceRules[$orderType].required) { if (-not $order.Contains($key)) { Fail "${label}: ordertype '$orderType' requires '$key'" } }
        foreach ($key in $script:PriceRules[$orderType].forbidden) { if ($order.Contains($key)) { Fail "${label}: ordertype '$orderType' must not have '$key'" } }
    }
    return $doc
}

function Order-Params($Order) {
    $params = @{}
    foreach ($key in $Order.Keys) { if ($key -ne 'label') { $params[$key] = $Order[$key] } }
    return $params
}

function Preflight($Credentials, $Doc) {
    $orders = $Doc['orders']; $pairs = @($orders | ForEach-Object { $_['pair'] } | Sort-Object -Unique)
    Write-Host ('=' * 60); Write-Host 'PRE-FLIGHT CHECKS'; Write-Host ('=' * 60)
    Write-Host "`n[1/4] Fetching pair specifications for $($pairs -join ', ')..."
    $info = Pair-Info $pairs
    foreach ($pair in $pairs) { Write-Host "      ${pair}: min=$($info[$pair]['ordermin'])  lot_decimals=$($info[$pair]['lot_decimals'])  pair_decimals=$($info[$pair]['pair_decimals'])" }
    Write-Host "`n[2/4] Fetching current prices..."
    $prices = @{}
    foreach ($pair in $pairs) {
        $ticker = Api 'Ticker' @{ pair = $pair }; Check-Response $ticker 'Ticker'
        $prices[$pair] = Dec @($ticker['result'].Values)[0]['c'][0]
        Write-Host "      ${pair}: last = $($prices[$pair])"
    }
    Write-Host "`n[3/4] Checking balances..."
    $response = Api 'Balance' @{} $Credentials; Check-Response $response 'Balance'
    $balances = $response['result']; $sellNeeded = @{}; $buyCost = @{}
    foreach ($order in $orders) {
        $pair = $order['pair']; $spec = $info[$pair]; $volume = Dec $order['volume']
        if ($order['type'] -ceq 'sell') {
            $asset = $spec['base']; $sellNeeded[$asset] = [decimal]$sellNeeded[$asset] + $volume
        } else {
            $asset = $spec['quote']; $price = $prices[$pair]
            if ($order['price'] -and $order['price'] -notmatch '^[+-]') { $price = Dec $order['price'] }
            $buyCost[$asset] = [decimal]$buyCost[$asset] + $price * $volume
        }
    }
    foreach ($asset in $sellNeeded.Keys) {
        $have = if ($balances.Contains($asset)) { Dec $balances[$asset] } else { [decimal]0 }
        if ($have -lt $sellNeeded[$asset]) { Fail "Insufficient $asset to sell. Required: $($sellNeeded[$asset]), Available: $have" }
        Write-Host "      OK ${asset}: selling $($sellNeeded[$asset]) of $have available"
    }
    foreach ($asset in $buyCost.Keys) {
        $have = if ($balances.Contains($asset)) { Dec $balances[$asset] } else { [decimal]0 }
        $warning = if ($have -lt $buyCost[$asset]) { ' (WARNING: may be insufficient)' } else { '' }
        Write-Host ('      {0}: buys cost ~ {1:N2}, available {2:N2}{3}' -f $asset,$buyCost[$asset],$have,$warning)
    }
    Write-Host "`n[4/4] Validating order precision and minimums..."
    foreach ($order in $orders) {
        $pair = $order['pair']; $spec = $info[$pair]; $label = Prop $order 'label' $pair
        $minimum = Dec (Prop $spec 'ordermin' '0')
        $lotDecimals = [int](Prop $spec 'lot_decimals' 8); $pairDecimals = [int](Prop $spec 'pair_decimals' 8)
        $volume = Dec $order['volume']
        if ($volume -lt $minimum) { Fail "${label}: volume $volume is below minimum $minimum" }
        if ($order['volume'] -match '\.(\d+)' -and $Matches[1].Length -gt $lotDecimals) { Fail "${label}: volume exceeds $lotDecimals decimal places" }
        if ($order.Contains('displayvol')) {
            $display = Dec $order['displayvol']
            if ($display -lt $minimum -or $display -gt $volume) { Fail "${label}: displayvol must be between $minimum and $volume" }
        }
        foreach ($field in @('price','price2')) {
            $value = Prop $order $field ''
            if ($value -and $value -notmatch '^[+-]') {
                $parsed = Dec $value
                $fraction = (DStr $parsed).Split('.')
                if ($fraction.Count -gt 1 -and $fraction[1].Length -gt $pairDecimals) { Fail "${label}: $field=$value exceeds $pairDecimals decimal places" }
            }
        }
        Write-Host "      OK $label"
    }
    Write-Host "`nPre-flight PASSED.`n"
}

function Show-Orders($Doc, [string]$Heading) {
    Write-Host ('=' * 60); Write-Host $Heading; Write-Host ('=' * 60)
    $index = 0
    foreach ($order in $Doc['orders']) {
        $index++; Write-Host "`n  [$index] $(Prop $order 'label' '(no label)')"
        foreach ($entry in (Order-Params $order).GetEnumerator()) { Write-Host ('        {0,-14} = {1}' -f $entry.Key,$entry.Value) }
    }
    Write-Host ''
}

function Validate-Orders($Credentials, $Doc) {
    Write-Host ('=' * 60); Write-Host 'SERVER VALIDATION - validate=true (no orders placed)'; Write-Host ('=' * 60)
    $index = 0; $failures = 0
    foreach ($order in $Doc['orders']) {
        $index++; $label = Prop $order 'label' "order $index"
        $params = Order-Params $order; $params['validate'] = 'true'
        $response = Api 'AddOrder' $params $Credentials
        if (@($response['error']).Count -gt 0) {
            Write-Host "  [$index/$($Doc['orders'].Count)] FAILED  $label : $($response['error'] -join ', ')"; $failures++
        } else {
            Write-Host "  [$index/$($Doc['orders'].Count)] OK      $label"
            Write-Host "        Kraken reads this as: $((Prop (Prop $response['result'] 'descr' @{}) 'order' ''))"
        }
    }
    if ($failures) { Fail "$failures order(s) failed server validation - nothing was placed" }
    Write-Host "All orders passed server validation.`n"
}

function Write-TradeLog($Entry) {
    $directory = Split-Path $script:LogFile
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    [IO.File]::AppendAllText($script:LogFile, (($Entry | ConvertTo-Json -Depth 20 -Compress) + "`n"), [Text.Encoding]::UTF8)
}

function Summary($Results, $Orders, [string]$Failed = '') {
    Write-Host "`n$('=' * 60)"; Write-Host 'SUMMARY'; Write-Host ('=' * 60)
    $totals = @{}
    foreach ($item in $Results) {
        Write-Host "  OK       $($item.label)`n           ID: $($item.txid)"
        $order = $item.order; $key = "$($order['pair'])|$($order['type'])"
        $totals[$key] = [decimal]$totals[$key] + (Dec $order['volume'])
    }
    if ($Failed) { Write-Host "`n  STOPPED at: $Failed" }
    foreach ($key in $totals.Keys) { $parts = $key.Split('|'); Write-Host "`n  Total $($parts[1]) volume placed on $($parts[0]): $($totals[$key])" }
    Write-Host ('=' * 60)
}

function Place($Options, $Positionals) {
    $accountName = Required $Options 'account'; $credentials = Account $accountName
    if ($Positionals.Count -ne 1) { Fail 'place requires one order file path' }
    $doc = Load-Order $Positionals[0] $accountName
    if ($doc['description']) { Write-Host "Order file : $($Positionals[0])`nDescription: $($doc['description'])`n" }
    Preflight $credentials $doc
    if (-not $Options.ContainsKey('live')) {
        Show-Orders $doc 'DRY-RUN - Orders that WOULD be sent to Kraken'
        Validate-Orders $credentials $doc
        Write-Host "Dry-run complete. Nothing was placed.`nTo place for real, run:`n  pwsh -File ./kraken.ps1 place $($Positionals[0]) --account $accountName --live"
        return
    }
    Show-Orders $doc 'LIVE MODE - Orders to be placed on Kraken'
    Write-Host "$('!' * 60)`n  WARNING: This will place $($doc['orders'].Count) REAL order(s) on the`n  '$accountName' Kraken account.`n$('!' * 60)"
    $answer = Read-Host "Type CONFIRM to place all $($doc['orders'].Count) orders, or anything else to abort"
    if ($answer.Trim() -cne 'CONFIRM') { Write-Host 'Aborted.'; return }
    $results = [Collections.Generic.List[object]]::new(); $index = 0
    foreach ($order in $doc['orders']) {
        $index++; $label = Prop $order 'label' "order $index"
        Write-Host "`n[$index/$($doc['orders'].Count)] $label"
        $params = Order-Params $order
        $response = Api 'AddOrder' $params $credentials
        $errors = @($response['error']); $txid = if ($errors.Count) { $null } else { @((Prop $response['result'] 'txid' @())) -join ', ' }
        $timestamp = UtcNow
        Write-TradeLog @{ ts = $timestamp; event = 'add_order'; account = $accountName; source_file = $Positionals[0]; label = $label; params = $params; txid = $txid; descr = (Prop (Prop $response['result'] 'descr' @{}) 'order' ''); error = $(if ($errors.Count) { $errors } else { $null }) }
        if ($errors.Count) { Write-Host "  FAILED: $($errors -join ', ')"; Summary $results $doc['orders'] $label; Fail 'Stopped after failed order' }
        Write-Host "  Order ID  : $txid`n  Status    : open`n  Timestamp : $timestamp"
        $results.Add(@{ label = $label; txid = $txid; order = $order })
    }
    Summary $results $doc['orders']
}

function Quantize-Down([decimal]$Value, [int]$Digits) {
    $scale = [decimal][Math]::Pow(10, $Digits)
    return [decimal]::Truncate($Value * $scale) / $scale
}
function Quantize-Price([decimal]$Value, [int]$Digits) {
    return [Math]::Round($Value, $Digits, [MidpointRounding]::ToEven)
}
function Allocate([decimal]$Total, $Weights, [int]$Digits) {
    if ($Weights.Count -lt 1 -or @($Weights | Where-Object { $_ -le 0 }).Count -gt 0) { Fail 'Weights and number of orders must be positive' }
    $quantum = [decimal]1 / [decimal][Math]::Pow(10, $Digits)
    if ($Total -le 0 -or $Total % $quantum -ne 0) { Fail "Total volume $Total is not a positive multiple of lot size $quantum" }
    $weightSum = [decimal]0; foreach ($weight in $Weights) { $weightSum += $weight }
    $shares = [decimal[]]::new($Weights.Count); $fractions = @(); $sum = [decimal]0
    for ($index = 0; $index -lt $Weights.Count; $index++) {
        $raw = $Total * $Weights[$index] / $weightSum
        $shares[$index] = Quantize-Down $raw $Digits
        $sum += $shares[$index]
        $fractions += @{ index = $index; fraction = $raw - $shares[$index] }
    }
    $ranked = @($fractions | Sort-Object -Property fraction -Descending)
    $remaining = [int](($Total - $sum) / $quantum)
    for ($index = 0; $index -lt $remaining; $index++) { $shares[$ranked[$index % $ranked.Count].index] += $quantum }
    $check = [decimal]0; foreach ($share in $shares) { $check += $share }
    if ($check -ne $Total) { Fail 'Allocation invariant violated' }
    return ,$shares
}

function Split-Table($Rows, [decimal]$Total) {
    Write-Host "`n$('  #             Price               Volume   % of total          Running sum')"
    Write-Host ('-' * 76)
    $running = [decimal]0; $index = 0
    foreach ($row in $Rows) {
        $index++; $running += $row.volume
        Write-Host ('{0,3} {1,16} {2,20} {3,9:N2}%   {4,20}' -f $index,$row.price,(DStr $row.volume),($row.volume / $Total * 100),(DStr $running))
    }
    $status = if ($running -eq $Total) { 'exact' } else { 'MISMATCH' }
    Write-Host "`nTotal: $(DStr $running) / $(DStr $Total)  $status"
    if ($status -ne 'exact') { Fail 'Generated volumes do not sum to total' }
}

function Write-OrderDoc($Options, $Orders, [string]$Description) {
    $accountName = Required $Options 'account'; $path = Required $Options 'output'
    if ((Test-Path -LiteralPath $path) -and -not $Options.ContainsKey('force')) { Fail "$path already exists - pass --force to overwrite" }
    $doc = [ordered]@{ version = 1; account = $accountName; description = $Description; generated_by = "kraken.ps1 $($script:OriginalArgs -join ' ')"; created = (UtcNow); orders = @($Orders) }
    $directory = Split-Path -Parent $path
    if ($directory) { [IO.Directory]::CreateDirectory($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($directory)) | Out-Null }
    $json = ConvertTo-Json -InputObject $doc -Depth 20
    [IO.File]::WriteAllText($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path), "$json`n", [Text.Encoding]::UTF8)
    Write-Host "`nWrote $path`nReview it, then dry-run:`n  pwsh -File ./kraken.ps1 place $path --account $accountName"
}

function Split-Orders([string]$Kind, $Options) {
    $pair = Required $Options 'pair'; $side = Required $Options 'side'
    if ($side -cnotin @('buy','sell')) { Fail '--side must be buy or sell' }
    $null = Required $Options 'account'; $null = Required $Options 'output'
    $total = Dec (Required $Options 'total-volume')
    $info = (Pair-Info @($pair))[$pair]; $minimum = Dec (Prop $info 'ordermin' '0')
    $lotDigits = [int]$info['lot_decimals']; $priceDigits = [int]$info['pair_decimals']
    $tif = Prop $Options 'tif' 'GTC'; $orders = @(); $rows = @()
    switch ($Kind) {
        'ladder' {
            $orderType = Prop $Options 'ordertype' 'limit'
            if ($orderType -eq 'market' -or -not $script:PriceRules.ContainsKey($orderType)) { Fail "Unsupported ladder ordertype '$orderType'" }
            $prices = @()
            if ($Options.ContainsKey('prices')) { $prices = @($Options['prices'].Split(',') | ForEach-Object { Dec $_ }) }
            else {
                $start = Dec (Required $Options 'price-start'); $end = Dec (Required $Options 'price-end'); $levels = [int](Required $Options 'levels')
                if ($levels -lt 2) { Fail '--levels must be at least 2' }
                for ($index = 0; $index -lt $levels; $index++) { $prices += Quantize-Price ($start + ($end - $start) * $index / ($levels - 1)) $priceDigits }
            }
            $levels = $prices.Count
            if ($levels -lt 1) { Fail 'At least one price is required' }
            foreach ($price in $prices) {
                if ($price -le 0 -or ((DStr $price).Split('.').Count -gt 1 -and (DStr $price).Split('.')[1].Length -gt $priceDigits)) { Fail "Price $price exceeds pair precision or is not positive" }
            }
            $weights = if ($Options.ContainsKey('weights')) { @( $Options['weights'].Split(',') | ForEach-Object { Dec $_ } ) } else { @(1..$levels | ForEach-Object { [decimal]1 }) }
            if ($weights.Count -ne $levels) { Fail "--weights has $($weights.Count) entries but there are $levels levels" }
            $shares = Allocate $total $weights $lotDigits
            $weightSum = [decimal]0; foreach ($weight in $weights) { $weightSum += $weight }
            $factor = [decimal]0
            if ($Options.ContainsKey('limit-offset')) { $factor = 1 + (Dec ($Options['limit-offset'].Trim().TrimEnd('%'))) / 100 }
            for ($index = 0; $index -lt $levels; $index++) {
                if ($shares[$index] -lt $minimum) { Fail "Level $($index + 1) volume $($shares[$index]) is below pair minimum $minimum" }
                $price = DStr $prices[$index]
                $percent = [Math]::Round(($weights[$index] / $weightSum * 100), 1, [MidpointRounding]::ToEven)
                $order = [ordered]@{ label = "L$($index + 1) - $orderType $side $percent% @ $price"; pair = $pair; type = $side; ordertype = $orderType; price = $price; volume = (DStr $shares[$index]) }
                if ($Options.ContainsKey('limit-offset')) { $order['price2'] = DStr (Quantize-Price ($prices[$index] * $factor) $priceDigits) }
                if ($Options.ContainsKey('trigger')) { $order['trigger'] = $Options['trigger'] }
                if ($Options.ContainsKey('oflags')) { $order['oflags'] = $Options['oflags'] }
                $order['timeinforce'] = $tif
                if ('price2' -in $script:PriceRules[$orderType].required -and -not $order.Contains('price2')) { Fail "ordertype '$orderType' needs --limit-offset" }
                if ('price2' -in $script:PriceRules[$orderType].forbidden) { $order.Remove('price2') }
                $orders += $order; $rows += @{ price = $price; volume = $shares[$index] }
            }
            $description = "$pair $side ladder - $levels levels, total $(DStr $total)"
        }
        'chunk' {
            $price = Required $Options 'price'; $chunks = [int](Required $Options 'chunks')
            if ($chunks -lt 1) { Fail '--chunks must be positive' }
            $shares = Allocate $total @(1..$chunks | ForEach-Object { [decimal]1 }) $lotDigits
            for ($index = 0; $index -lt $chunks; $index++) {
                if ($shares[$index] -lt $minimum) { Fail "Chunk $($index + 1) volume is below pair minimum $minimum" }
                $order = [ordered]@{ label = "C$($index + 1)/$chunks - limit $side @ $price"; pair = $pair; type = $side; ordertype = 'limit'; price = $price; volume = (DStr $shares[$index]); timeinforce = $tif }
                if ($Options.ContainsKey('oflags')) { $order['oflags'] = $Options['oflags'] }
                $orders += $order; $rows += @{ price = $price; volume = $shares[$index] }
            }
            $description = "$pair $side split into $chunks chunks @ $price"
        }
        'iceberg' {
            $price = Required $Options 'price'; $display = Dec (Required $Options 'display')
            if ($total -lt $minimum -or $display -lt $minimum -or $display -gt $total -or $display -lt $total / 25) { Fail 'Display volume must meet pair minimum, be at most total, and be at least 1/25 of total' }
            $order = [ordered]@{ label = "Iceberg - limit $side $(DStr $total) @ $price (display $(DStr $display))"; pair = $pair; type = $side; ordertype = 'limit'; price = $price; volume = (Required $Options 'total-volume'); displayvol = (Required $Options 'display'); timeinforce = $tif }
            if ($Options.ContainsKey('oflags')) { $order['oflags'] = $Options['oflags'] }
            $orders = @($order); $rows = @(@{ price = $price; volume = $total })
            $description = "$pair $side iceberg @ $price, display $(DStr $display)"
        }
        default { Fail 'split requires ladder, chunk, or iceberg' }
    }
    Split-Table $rows $total
    Write-OrderDoc $Options $orders $description
}

function Required($Options, [string]$Key) {
    if (-not $Options.ContainsKey($Key) -or [string]::IsNullOrWhiteSpace([string]$Options[$Key])) { Fail "--$Key is required" }
    return $Options[$Key]
}

function Parse-Options($Tokens, $Positionals, $Options) {
    $flags = @('live','force'); $values = @('account','count','pair','side','total-volume','price','display','chunks','output','o','oflags','tif','ordertype','levels','price-start','price-end','prices','weights','limit-offset','trigger')
    for ($index = 0; $index -lt $Tokens.Count; $index++) {
        $token = [string]$Tokens[$index]
        if ($token -match '^(--[\w-]+|-o)(?:=(.*))?$') {
            $name = $Matches[1].TrimStart('-'); $inline = $Matches.ContainsKey(2); $value = if ($inline) { $Matches[2] } else { $null }
            if ($name -eq 'o') { $name = 'output' }
            if ($name -in $flags) { if ($inline) { Fail "--$name does not take a value" }; $Options[$name] = $true; continue }
            if ($name -notin $values) { Fail "Unknown option $token" }
            if (-not $inline) {
                $index++
                if ($index -ge $Tokens.Count) { Fail "--$name needs a value" }
                $value = [string]$Tokens[$index]
                if ($value.StartsWith('--')) { Fail "--$name needs a value" }
            }
            $Options[$name] = $value
        } else { $Positionals.Add($token) }
    }
}

function Main($Tokens) {
    if ($Tokens.Count -eq 0) { Fail 'Usage: pwsh -File ./kraken.ps1 balance|ticker|pair-info|open-orders|closed-orders|trades|place|split|cancel|cancel-all ...' }
    $command = $Tokens[0]; $kind = '' ; $skip = 1
    if ($command -eq 'split' -and $Tokens.Count -gt 1) { $kind = $Tokens[1]; $skip = 2 }
    $options = @{}; $positionals = [Collections.Generic.List[string]]::new()
    Parse-Options @($Tokens | Select-Object -Skip $skip) $positionals $options
    switch ($command) {
        'balance' {
            $response = Api 'Balance' @{} (Account (Required $options 'account')); Check-Response $response 'Balance'
            $nonzero = @($response['result'].Keys | Where-Object { (Dec $response['result'][$_]) -ne 0 } | Sort-Object)
            if (-not $nonzero.Count) { Write-Host 'No non-zero balances.'; return }
            Write-Host ('{0,-12} {1,24}' -f 'Asset','Balance'); Write-Host ('-' * 38)
            foreach ($asset in $nonzero) { Write-Host ('{0,-12} {1,24:N8}' -f $asset,(Dec $response['result'][$asset])) }
        }
        'ticker' {
            if (-not $positionals.Count) { Fail 'ticker requires at least one pair' }
            foreach ($pair in $positionals) {
                $response = Api 'Ticker' @{ pair = $pair }
                if (@($response['error']).Count) { Write-Host "$pair ERROR: $($response['error'] -join ', ')"; continue }
                $ticker = @($response['result'].Values)[0]
                Write-Host "${pair} last=$($ticker['c'][0])  bid=$($ticker['b'][0])  ask=$($ticker['a'][0])  24h: low=$($ticker['l'][1]) high=$($ticker['h'][1]) vol=$($ticker['v'][1])"
            }
        }
        'pair-info' {
            if ($positionals.Count -ne 1) { Fail 'pair-info requires one pair' }
            $pair = $positionals[0]; $info = (Pair-Info @($pair))[$pair]
            Write-Host "Pair            : $pair ($($info['wsname']))`nBase / Quote    : $($info['base']) / $($info['quote'])`nMin order size  : $($info['ordermin'])`nMin order cost  : $(Prop $info 'costmin' 'n/a')`nLot decimals    : $($info['lot_decimals'])  (volume precision)`nPair decimals   : $($info['pair_decimals'])  (price precision)`nOrder types     : $(@($script:PriceRules.Keys | Sort-Object) -join ', ')"
        }
        'open-orders' {
            $response = Api 'OpenOrders' @{} (Account (Required $options 'account')); Check-Response $response 'OpenOrders'
            $orders = Prop $response['result'] 'open' @{}
            Write-Host "Open orders: $($orders.Count)`n"; Print-Orders $orders
        }
        'closed-orders' {
            $response = Api 'ClosedOrders' @{} (Account (Required $options 'account')); Check-Response $response 'ClosedOrders'
            $count = [int](Prop $options 'count' 20); $closed = Prop $response['result'] 'closed' @{}
            $recent = [ordered]@{}
            foreach ($entry in @($closed.GetEnumerator() | Sort-Object { [decimal](Prop $_.Value 'closetm' 0) } -Descending | Select-Object -First $count)) { $recent[$entry.Key] = $entry.Value }
            Write-Host "Closed orders (most recent $($recent.Count)):`n"; Print-Orders $recent
        }
        'trades' {
            $response = Api 'TradesHistory' @{} (Account (Required $options 'account')); Check-Response $response 'TradesHistory'
            $count = [int](Prop $options 'count' 20); $trades = Prop $response['result'] 'trades' @{}
            $recent = @($trades.Values | Sort-Object { [decimal](Prop $_ 'time' 0) } -Descending | Select-Object -First $count)
            Write-Host "Recent fills (most recent $($recent.Count)):`n"
            if (-not $recent.Count) { Write-Host '(none)'; return }
            Write-Host ('{0,-20} {1,-10} {2,-5} {3,14} {4,18} {5,14} {6,10}' -f 'Time (UTC)','Pair','Type','Price','Volume','Cost','Fee'); Write-Host ('-' * 98)
            foreach ($trade in $recent) {
                $time = [DateTimeOffset]::FromUnixTimeSeconds([long][Math]::Floor([double]$trade['time'])).UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss')
                Write-Host ('{0,-20} {1,-10} {2,-5} {3,14} {4,18} {5,14} {6,10}' -f $time,$trade['pair'],$trade['type'],$trade['price'],$trade['vol'],$trade['cost'],$trade['fee'])
            }
        }
        'place' { Place $options $positionals }
        'split' { Split-Orders $kind $options }
        'cancel' {
            if (-not $positionals.Count) { Fail 'cancel requires at least one TxID' }
            $accountName = Required $options 'account'; $credentials = Account $accountName
            $response = Api 'QueryOrders' @{ txid = $positionals -join ',' } $credentials; Check-Response $response 'QueryOrders'
            Write-Host "Orders to cancel:`n"; Print-Orders $response['result']
            foreach ($txid in $positionals) { if (-not $response['result'].Contains($txid)) { Fail "TxID not found on this account: $txid" } }
            if ((Read-Host "Cancel $($positionals.Count) order(s)? [y/N]").Trim() -cne 'y') { Write-Host 'Aborted.'; return }
            foreach ($txid in $positionals) {
                $result = Api 'CancelOrder' @{ txid = $txid } $credentials
                $errors = @($result['error'])
                Write-TradeLog @{ ts = (UtcNow); event = 'cancel_order'; account = $accountName; txid = $txid; error = $(if ($errors.Count) { $errors } else { $null }) }
                if ($errors.Count) { Write-Host "  FAILED  ${txid}: $($errors -join ', ')" } else { Write-Host "  OK      $txid cancelled" }
            }
        }
        'cancel-all' {
            $accountName = Required $options 'account'; $credentials = Account $accountName
            $response = Api 'OpenOrders' @{} $credentials; Check-Response $response 'OpenOrders'
            $orders = Prop $response['result'] 'open' @{}
            if (-not $orders.Count) { Write-Host 'No open orders to cancel.'; return }
            Write-Host "This will cancel ALL $($orders.Count) open order(s) on '$accountName':`n"; Print-Orders $orders
            if ((Read-Host 'Type CONFIRM to cancel all of these orders').Trim() -cne 'CONFIRM') { Write-Host 'Aborted.'; return }
            $result = Api 'CancelAll' @{} $credentials
            $errors = @($result['error'])
            Write-TradeLog @{ ts = (UtcNow); event = 'cancel_all'; account = $accountName; count = (Prop $result['result'] 'count'); error = $(if ($errors.Count) { $errors } else { $null }) }
            Check-Response $result 'CancelAll'
            Write-Host "Cancelled $($result['result']['count']) order(s)."
        }
        default { Fail "Unknown command '$command'" }
    }
}

try { Main $script:OriginalArgs }
catch { [Console]::Error.WriteLine("`n$($_.Exception.Message)"); exit 1 }