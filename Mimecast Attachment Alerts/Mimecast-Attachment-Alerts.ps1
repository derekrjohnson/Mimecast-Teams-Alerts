#Setup required variables
$baseUrl = "https://usb-api.mimecast.com"
$uri = "/api/ttp/attachment/get-logs"
$url = $baseUrl + $uri
$accessKey = Ninja-Property-Get "mimecastSecurityAlertsAccessKey"
$secretKey = Ninja-Property-Get "mimecastSecurityAlertsSecretKey"
$appId = Ninja-Property-Get "mimecastSecurityAlertsAppId"
$appKey = Ninja-Property-Get "mimecastSecurityAlertsAppKey"

# Generate request header values
$hdrDate = (Get-Date).ToUniversalTime().ToString("ddd, dd MMM yyyy HH:mm:ss UTC")
$requestId = [guid]::NewGuid().guid

# Create the HMAC SHA1 of the Base64 decoded secret key for the Authorization header
$sha = New-Object System.Security.Cryptography.HMACSHA1
$sha.key = [Convert]::FromBase64String($secretKey)
$sig = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($hdrDate + ":" + $requestId + ":" + $uri + ":" + $appKey))
$sig = [Convert]::ToBase64String($sig)

# Create Headers
$headers = @{
    "Authorization" = "MC " + $accessKey + ":" + $sig
    "x-mc-date" = $hdrDate
    "x-mc-app-id" = $appId
    "x-mc-req-id" = $requestId
    "Content-Type" = "application/json"
}

# Get the current date and time
$currentDateTime = Get-Date

# Calculate the date and time 24 hours ago
$fromDateTime = $currentDateTime.AddMinutes(-1)

# Format the date and time strings
$formattedFromDateTime = $fromDateTime.ToString("yyyy-MM-ddTHH:mm:sszzzz")
$formattedToDateTime = $currentDateTime.ToString("yyyy-MM-ddTHH:mm:sszzzz")

# Create post body
$postBody = @{
    "meta" = @{
        "pagination" = @{
            "pageSize" = 25
        }
    }
    "data" = @(
        @{
            "oldestFirst" = $true
            "taggedMalicious" = $true
            "from" = $formattedFromDateTime
            "to" = $formattedToDateTime
            "route" = "all"
            "result" = "malicous"

        }
    )
}

# Convert the PowerShell object to JSON
$jsonData = ConvertTo-Json -InputObject $postBody -Depth 10

try {
    # Send Request and get the response
    $response = Invoke-RestMethod -Method Post -Headers $headers -Body $jsonData -Uri $url

    # The web request was successful (status code 200)
    Write-Host "Successfully authenticated with the endpoint."

} catch {
    # An exception occurred during the web request
    Write-Host "Failed to authenticate with the endpoint."
    Write-Host "Error message: $($_.Exception.Message)"
}

# Check if the response contains data
if ($response.data[0].attachmentLogs) {
    foreach ($logObject in $response.data[0].attachmentLogs) {
        Write-Host "Data received from the API. Sending to Teams webhook..."
        # Create the facts array for the current JSON object
        $facts = @(
            @{
                "name" = "Result"
                "value" = $logObject.result
            },
            @{
                "name" = "Date"
                "value" = $logObject.date
            },
            @{
                "name" = "Sender Address"
                "value" = $logObject.senderAddress
            },
            @{
                "name" = "File Name"
                "value" = $logObject.fileName
            },
            @{
                "name" = "Action Triggered"
                "value" = $logObject.actiontriggered
            },
            @{
                "name" = "Route"
                "value" = $logObject.route
            },
            @{
                "name" = "Details"
                "value" = $logObject.details
            },
            @{
                "name" = "Recipient Address"
                "value" = $logObject.recipientAddress
            },
            @{
                "name" = "File Type"
                "value" = $logObject.fileType
            },
            @{
                "name" = "File Hash"
                "value" = $logObject.fileHash
            }
        )

        # Create the message object
        $message = @{
            "@type" = "MessageCard"
            "@context" = "http://schema.org/extensions"
            "themeColor" = "0076D7"
            "summary" = "Summary of the message"
            "sections" = @(
                @{
                    "activityTitle" = "Mimecast Attatchment Alert"
                    "facts" = $facts
                }
            )
            "markdown" = $true
        }

        # Convert the message object to JSON
        $jsonMessage = ConvertTo-Json -InputObject $message -Depth 10

        # Set the webhook URL
        $webhookUrl = <Your Webhook URL>
        # Send POST request to the webhook URL
        Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $jsonMessage -ContentType "application/json" 

        Write-Host "Log data has been sent to the Teams webhook."
    }
} else {
    Write-Host "No malicous attachment logs received from the API."
}
