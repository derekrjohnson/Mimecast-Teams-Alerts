#Setup required variables
$baseUrl = "https://usb-api.mimecast.com"
$uri = "/api/ttp/url/get-logs"
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
            "scanResult" = "malicious"

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
if ($response.data[0].clickLogs) {
    foreach ($logObject in $response.data[0].clickLogs) {
        Write-Host "Data received from the API. Sending to Teams webhook..."
        # Create the facts array for the current JSON object
        $facts = @(
            @{
                "name" = "User Email Address"
                "value" = $logObject.userEmailAddress
            },
            @{
                "name" = "From User Email Address"
                "value" = $logObject.fromUserEmailAddress
            },
            @{
                "name" = "URL"
                "value" = $logObject.url
            },
            @{
                "name" = "TTP Definition"
                "value" = $logObject.ttpDefinition
            },
            @{
                "name" = "Subject"
                "value" = $logObject.subject
            },
            @{
                "name" = "Action"
                "value" = $logObject.action
            },
            @{
                "name" = "Admin Override"
                "value" = $logObject.adminOverride
            },
            @{
                "name" = "User Override"
                "value" = $logObject.userOverride
            },
            @{
                "name" = "Scan Result"
                "value" = $logObject.scanResult
            },
            @{
                "name" = "Category"
                "value" = $logObject.category
            },
            @{
                "name" = "Sending IP"
                "value" = $logObject.sendingIp
            },
            @{
                "name" = "User Awareness Action"
                "value" = $logObject.userAwarenessAction
            },
            @{
                "name" = "Date"
                "value" = $logObject.date
            },
            @{
                "name" = "Actions"
                "value" = $logObject.actions
            },
            @{
                "name" = "Route"
                "value" = $logObject.route
            },
            @{
                "name" = "Creation Method"
                "value" = $logObject.creationMethod
            },
            @{
                "name" = "Email Parts Description"
                "value" = $logObject.emailPartsDescription -join ", "
            },
            @{
                "name" = "Message ID"
                "value" = $logObject.messageId
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
                    "activityTitle" = "Mimecast URL Alert"
                    "facts" = $facts
                }
            )
            "markdown" = $true
        }

        # Convert the message object to JSON
        $jsonMessage = ConvertTo-Json -InputObject $message -Depth 10

        write-host $jsonMessage

        # Set the webhook URL
        $webhookUrl = <Your Webhook URL>
        # Send POST request to the webhook URL
        Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $jsonMessage -ContentType "application/json" -Verbose

        Write-Host "Log data has been sent to the Teams webhook."
    }
} else {
    Write-Host "No malicous URL Logs received from the API."
}
