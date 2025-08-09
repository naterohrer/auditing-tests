# URL Category Access Checker
# Purpose: Test web filtering and URL categorization policies
# Use only in authorized testing environments with proper approval

param(
    [string]$LogFile = "url_category_test_results.log",
    [switch]$Verbose,
    [switch]$ExportCSV,
    [string]$CSVFile = "url_category_results.csv"
)

# Initialize results array
$Global:TestResults = @()

# Define URL categories and test sites
$URLCategories = @{
    "Social Media" = @(
        "https://www.facebook.com",
        "https://www.twitter.com",
        "https://www.instagram.com",
        "https://www.linkedin.com",
        "https://www.snapchat.com",
        "https://www.tiktok.com",
        "https://www.reddit.com",
        "https://www.pinterest.com",
        "https://www.youtube.com",
        "https://www.discord.com"
    )
    
    "File Sharing" = @(
        "https://www.dropbox.com",
        "https://drive.google.com",
        "https://onedrive.live.com",
        "https://www.mediafire.com",
        "https://www.4shared.com",
        "https://www.rapidshare.com",
        "https://www.sendspace.com",
        "https://www.zippyshare.com",
        "https://www.wetransfer.com",
        "https://mega.nz"
    )
    
    "Adult Content" = @(
        "https://www.playboy.com",
        "https://www.maxim.com",
        "https://www.fhm.com",
        "https://www.hustler.com",
        "https://www.penthouse.com",
        "https://www.adultswim.com",
        "https://www.vice.com/en/topic/sex",
        "https://www.cosmopolitan.com/sex-love",
        "https://www.menshealth.com/sex-women",
        "https://www.askmen.com/dating"
    )
    
    "Gaming" = @(
        "https://store.steampowered.com",
        "https://www.epicgames.com",
        "https://www.twitch.tv",
        "https://www.roblox.com",
        "https://www.minecraft.net",
        "https://www.ea.com",
        "https://www.ubisoft.com",
        "https://www.blizzard.com",
        "https://www.xbox.com",
        "https://www.playstation.com"
    )
    
    "Dating Sites" = @(
        "https://www.match.com",
        "https://www.eharmony.com",
        "https://www.pof.com",
        "https://www.okcupid.com",
        "https://www.bumble.com",
        "https://www.hinge.co",
        "https://www.christianmingle.com",
        "https://www.zoosk.com",
        "https://www.badoo.com",
        "https://www.tinder.com"
    )
    
    "Streaming Media" = @(
        "https://www.netflix.com",
        "https://www.hulu.com",
        "https://www.amazon.com/prime",
        "https://www.disney.com",
        "https://www.hbo.com",
        "https://www.paramount.com",
        "https://www.peacocktv.com",
        "https://www.apple.com/tv",
        "https://www.crunchyroll.com",
        "https://www.funimation.com"
    )
    
    "Shopping" = @(
        "https://www.amazon.com",
        "https://www.ebay.com",
        "https://www.walmart.com",
        "https://www.target.com",
        "https://www.bestbuy.com",
        "https://www.costco.com",
        "https://www.alibaba.com",
        "https://www.etsy.com",
        "https://www.shopify.com",
        "https://www.wish.com"
    )
    
    "News & Media" = @(
        "https://www.cnn.com",
        "https://www.bbc.com",
        "https://www.reuters.com",
        "https://www.ap.org",
        "https://www.nytimes.com",
        "https://www.washingtonpost.com",
        "https://www.wsj.com",
        "https://www.bloomberg.com",
        "https://www.npr.org",
        "https://www.usatoday.com"
    )
    
    "Weapons & Military" = @(
        "https://www.gunsandammo.com",
        "https://www.military.com",
        "https://www.americanrifleman.org",
        "https://www.tactical-life.com",
        "https://www.outdoorlife.com/hunting",
        "https://www.fieldandstream.com/hunting",
        "https://www.rifleshootermag.com",
        "https://www.policemag.com",
        "https://www.militarytimes.com",
        "https://www.defensenews.com"
    )
    
    "Anonymous Proxy" = @(
        "https://www.torproject.org",
        "https://www.hidemyass.com",
        "https://www.nordvpn.com",
        "https://www.expressvpn.com",
        "https://www.surfshark.com",
        "https://www.cyberghostvpn.com",
        "https://www.privateinternetaccess.com",
        "https://www.protonvpn.com",
        "https://www.tunnelbear.com",
        "https://www.hotspotshield.com"
    )
    
    "Suspicious/Malware" = @(
        "https://malware-traffic-analysis.net",
        "https://www.hybrid-analysis.com",
        "https://www.virustotal.com",
        "https://urlvoid.com",
        "https://www.malwaredomainlist.com",
        "https://www.phishtank.com",
        "https://zeustracker.abuse.ch",
        "https://www.spamhaus.org",
        "https://www.malwareurl.com",
        "https://www.cleanmx.de"
    )
    
    "Cryptocurrency" = @(
        "https://www.coinbase.com",
        "https://www.binance.com",
        "https://www.kraken.com",
        "https://www.bitfinex.com",
        "https://www.gemini.com",
        "https://www.blockchain.com",
        "https://www.bitcoin.org",
        "https://ethereum.org",
        "https://www.coindesk.com",
        "https://www.cryptocompare.com"
    )
}

# Simple logging function
function Write-TestLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Write-Host $logEntry
    Add-Content -Path $LogFile -Value $logEntry
}

# Test URL accessibility
function Test-URLAccess {
    param(
        [string]$URL,
        [string]$Category
    )
    
    $result = @{
        URL = $URL
        Category = $Category
        Status = "Unknown"
        ResponseCode = $null
        ResponseTime = $null
        Blocked = $false
        Error = $null
        Timestamp = Get-Date
    }
    
    try {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $response = $null
        
        # First attempt with HEAD request
        try {
            $response = Invoke-WebRequest -Uri $URL -Method HEAD -TimeoutSec 7 -ErrorAction Stop
        } catch {
            # If HEAD fails with method not allowed or other error, retry with GET and spoofed user agent
            if ($_.Exception.Message -match '405|Method Not Allowed|MethodNotAllowed' -or $_.Exception.Message -match 'forbidden|blocked') {
                Write-TestLog "HEAD request failed for $URL, retrying with GET and user agent" "INFO"
                $userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"
                $response = Invoke-WebRequest -Uri $URL -Method GET -UserAgent $userAgent -TimeoutSec 7 -ErrorAction Stop
            } else {
                # Re-throw the original exception if it's not a method not allowed error
                throw
            }
        }
        
        $stopwatch.Stop()
        
        $result.ResponseTime = $stopwatch.ElapsedMilliseconds
        $result.ResponseCode = $response.StatusCode
        $result.Status = "Accessible"
        
        if ($Verbose) {
            Write-TestLog "SUCCESS: $URL - HTTP $($response.StatusCode) $($stopwatch.ElapsedMilliseconds)ms" "SUCCESS"
        }
        
    } catch {
        if ($stopwatch -and $stopwatch.IsRunning) { 
            $stopwatch.Stop() 
        }
        $result.ResponseTime = if ($stopwatch) { $stopwatch.ElapsedMilliseconds } else { $null }
        $result.Error = $_.Exception.Message
        
        if ($_.Exception.Message -match 'blocked|filtered|denied|403|proxy') {
            $result.Status = "Blocked"
            $result.Blocked = $true
            $result.ResponseCode = 403
            Write-TestLog "BLOCKED: $URL" "BLOCKED"
        } elseif ($_.Exception.Message -match 'timeout|timed out') {
            $result.Status = "Timeout"
            Write-TestLog "TIMEOUT: $URL" "TIMEOUT"
        } elseif ($_.Exception.Message -match '404|not found') {
            $result.Status = "Not Found"
            $result.ResponseCode = 404
            Write-TestLog "NOT FOUND: $URL" "NOTFOUND"
        } else {
            $result.Status = "Error"
            Write-TestLog "ERROR: $URL - $($_.Exception.Message)" "ERROR"
        }
    }
    
    return $result
}

# Test all URLs in a category
function Test-CategoryURLs {
    param(
        [string]$CategoryName,
        [array]$URLs
    )
    
    Write-TestLog "Testing category: $CategoryName ($($URLs.Count) URLs)" "INFO"
    
    $categoryResults = @()
    $accessibleCount = 0
    $blockedCount = 0
    $errorCount = 0
    
    foreach ($url in $URLs) {
        $result = Test-URLAccess -URL $url -Category $CategoryName
        $categoryResults += $result
        $Global:TestResults += $result
        
        switch ($result.Status) {
            "Accessible" { $accessibleCount++ }
            "Blocked" { $blockedCount++ }
            default { $errorCount++ }
        }
        
        Start-Sleep -Milliseconds 200
    }
    
    # Calculate percentages
    $totalCount = $URLs.Count
    $accessiblePercentage = [math]::Round(($accessibleCount / $totalCount) * 100, 2)
    $blockedPercentage = [math]::Round(($blockedCount / $totalCount) * 100, 2)
    $errorPercentage = [math]::Round(($errorCount / $totalCount) * 100, 2)
    
    $categorySummary = @{
        Category = $CategoryName
        TotalSites = $totalCount
        Accessible = $accessibleCount
        Blocked = $blockedCount
        Errors = $errorCount
        AccessiblePercentage = $accessiblePercentage
        BlockedPercentage = $blockedPercentage
        ErrorPercentage = $errorPercentage
        Results = $categoryResults
    }
    
    Write-TestLog "Category Summary - $CategoryName" "SUMMARY"
    Write-TestLog "  Accessible: $accessibleCount/$totalCount ($accessiblePercentage percent)" "SUMMARY"
    Write-TestLog "  Blocked: $blockedCount/$totalCount ($blockedPercentage percent)" "SUMMARY"
    Write-TestLog "  Errors: $errorCount/$totalCount ($errorPercentage percent)" "SUMMARY"
    Write-TestLog "----------------------------------------" "INFO"
    
    return $categorySummary
}

# Generate detailed report
function Generate-Report {
    param([array]$CategorySummaries)
    
    Write-TestLog "" "REPORT"
    Write-TestLog "=== DETAILED URL CATEGORY ACCESS REPORT ===" "REPORT"
    Write-TestLog "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "REPORT"
    Write-TestLog "Total Categories Tested: $($CategorySummaries.Count)" "REPORT"
    Write-TestLog "Total URLs Tested: $($Global:TestResults.Count)" "REPORT"
    Write-TestLog "" "REPORT"
    
    # Overall statistics
    $totalAccessible = ($Global:TestResults | Where-Object { $_.Status -eq "Accessible" }).Count
    $totalBlocked = ($Global:TestResults | Where-Object { $_.Status -eq "Blocked" }).Count
    $totalErrors = $Global:TestResults.Count - $totalAccessible - $totalBlocked
    
    Write-TestLog "=== OVERALL STATISTICS ===" "REPORT"
    $accessiblePercent = [math]::Round(($totalAccessible / $Global:TestResults.Count) * 100, 2)
    $blockedPercent = [math]::Round(($totalBlocked / $Global:TestResults.Count) * 100, 2)
    $errorPercent = [math]::Round(($totalErrors / $Global:TestResults.Count) * 100, 2)
    Write-TestLog "Total Accessible: $totalAccessible ($accessiblePercent percent)" "REPORT"
    Write-TestLog "Total Blocked: $totalBlocked ($blockedPercent percent)" "REPORT"
    Write-TestLog "Total Errors: $totalErrors ($errorPercent percent)" "REPORT"
    Write-TestLog "" "REPORT"
    
    # Category breakdown
    Write-TestLog "=== CATEGORY BREAKDOWN ===" "REPORT"
    foreach ($summary in $CategorySummaries | Sort-Object BlockedPercentage -Descending) {
        Write-TestLog "$($summary.Category):" "REPORT"
        Write-TestLog "  Sites Tested: $($summary.TotalSites)" "REPORT"
        Write-TestLog "  Accessible: $($summary.Accessible) ($($summary.AccessiblePercentage) percent)" "REPORT"
        Write-TestLog "  Blocked: $($summary.Blocked) ($($summary.BlockedPercentage) percent)" "REPORT"
        Write-TestLog "  Errors: $($summary.Errors) ($($summary.ErrorPercentage) percent)" "REPORT"
        
        # List blocked sites
        $blockedSites = $summary.Results | Where-Object { $_.Status -eq "Blocked" }
        if ($blockedSites.Count -gt 0) {
            Write-TestLog "  Blocked Sites:" "REPORT"
            foreach ($site in $blockedSites) {
                Write-TestLog "    - $($site.URL)" "REPORT"
            }
        }
        
        # List error sites
        $errorSites = $summary.Results | Where-Object { $_.Status -notin @("Accessible", "Blocked") }
        if ($errorSites.Count -gt 0) {
            Write-TestLog "  Error Sites:" "REPORT"
            foreach ($site in $errorSites) {
                Write-TestLog "    - $($site.URL) ($($site.Status))" "REPORT"
            }
        }
        
        Write-TestLog "" "REPORT"
    }
    
    # Top blocked categories
    Write-TestLog "=== TOP BLOCKED CATEGORIES ===" "REPORT"
    $topBlocked = $CategorySummaries | Sort-Object BlockedPercentage -Descending | Select-Object -First 5
    foreach ($category in $topBlocked) {
        Write-TestLog "$($category.Category): $($category.BlockedPercentage) percent blocked" "REPORT"
    }
    
    # Top accessible categories
    Write-TestLog "" "REPORT"
    Write-TestLog "=== TOP ACCESSIBLE CATEGORIES ===" "REPORT"
    $topAccessible = $CategorySummaries | Sort-Object AccessiblePercentage -Descending | Select-Object -First 5
    foreach ($category in $topAccessible) {
        Write-TestLog "$($category.Category): $($category.AccessiblePercentage) percent accessible" "REPORT"
    }
}

# Export results to CSV
function Export-ToCSV {
    param([string]$FilePath)
    
    Write-TestLog "Exporting results to CSV: $FilePath" "INFO"
    
    $Global:TestResults | Select-Object Category, URL, Status, ResponseCode, ResponseTime, Blocked, Error, Timestamp | 
        Export-Csv -Path $FilePath -NoTypeInformation
    
    Write-TestLog "CSV export completed" "SUCCESS"
}

# Main execution
try {
    Write-TestLog "Starting URL Category Access Testing" "START"
    Write-TestLog "Timeout setting: 7 seconds" "INFO"
    Write-TestLog "Log file: $LogFile" "INFO"
    
    if ($ExportCSV) {
        Write-TestLog "CSV export enabled: $CSVFile" "INFO"
    }
    
    $categorySummaries = @()
    
    # Test each category
    foreach ($categoryName in $URLCategories.Keys) {
        $urls = $URLCategories[$categoryName]
        $summary = Test-CategoryURLs -CategoryName $categoryName -URLs $urls
        $categorySummaries += $summary
    }
    
    # Generate comprehensive report
    Generate-Report -CategorySummaries $categorySummaries
    
    # Export to CSV if requested
    if ($ExportCSV) {
        Export-ToCSV -FilePath $CSVFile
    }
    
    Write-TestLog "URL Category Testing completed successfully!" "COMPLETE"
    Write-TestLog "Results saved to: $LogFile" "INFO"
    
} catch {
    Write-TestLog "Critical error during testing: $($_.Exception.Message)" "CRITICAL"
} finally {
    Write-TestLog "Testing session ended: $(Get-Date)" "INFO"
}

# Display final summary
Write-Host ""
Write-Host "=== URL CATEGORY TEST SUMMARY ==="
Write-Host "Total URLs tested: $($Global:TestResults.Count)"
Write-Host "Log file: $LogFile"
if ($ExportCSV) {
    Write-Host "CSV file: $CSVFile"
}
Write-Host "Review the detailed log for complete analysis"
