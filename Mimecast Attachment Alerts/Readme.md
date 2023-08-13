# README #

### Mimecast Attachment Alerts Script ###

* This script authenticates and sends a post request to the $uri = "/api/ttp/attachment/get-logs". Then it sends those logs to the Security Alerts Teams channel.
* Version 1.0 2023-07-28
* Author Derek Johnson
* [Learn Markdown](https://bitbucket.org/tutorials/markdowndemo)

### Getting Started ###

 - To implement this script in NinjaRmm add it to your script library on Ninja.
 - Add the script to an existing or new policy that will be assigned different devices. The current policy this script is attached to is UM Windows Server - Child - JVM - Mimecast Alerts which is assigned to the umopsvr.
 - Make sure to schedule the script to run every minute or to whatever look back time you want when adding the script to a policy. This line '''$fromDateTime = $currentDateTime.AddMinutes(-1)''' is where you can set the desired lookback period in the script.

### How it works ###

* The code first sets the endpoint url to a variahble, access key to a variable, secret key to a variable, app id to a variable, and app key to a variable.
    * These variables are pulled from hidden custom global fields in ninjat that have read only permissions for scripts and a single device scope. (To edit these you can change the permissions to be modifiable by Technicians) 
* Next the script will generate headers for the request, more details can be found on this from the [Mimecast Documentation](https://integrations.mimecast.com/documentation/api-overview/authorization/). 
* This endpoint requires you to send a post request with body data to set the lookback range for logs. 
	* The script uses the current date time and subtracts a single minute, this can be customized for different use cases.
* The body of this web request also contains a taggedMalicous field and a scanResult field which filter what logs are sent to the webhook. (This reduces noise and means only medium-critical level alerts from any source will be sent to the channel.)

```
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
            "result" = "malicious"

        }
    )
}
```

* Next the script sends the request but it uses try and catch to output if the request was succesful and if it isn't what the error code is. This is handy for debugging the script.

```
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
```

* The next step is to send the response.data that is stored witht he $response variable and format it in a way to send to the Teams Webhook URL.
	* If there is data from the response of the previous web request this script sends a teams webhook for each log found. The $facts variable is formatted similiarly to the SiemPy.ps1 script. 
	* The name and value fields have to match how the Mimecast log data is formatted to send all the correct data to the webhook.
    
```
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
```

* Finally the log(s) are sent to the webhook URL and if this suceeds then the script outputs a success message. If the condition that the for loop is in returns false, meaning no data was found from the api, then the script returns a no data found message.

### Reference Links ###
* [Authentication and Headers](https://integrations.mimecast.com/documentation/api-overview/authentication-scripts-server-apps/)
* [Endpoint guide and example](https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-ttp-attachment-protection-logs/)
