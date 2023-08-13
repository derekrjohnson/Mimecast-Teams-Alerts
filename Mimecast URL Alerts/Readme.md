# README #

### Mimecast Security Alerts Script ###

* This script authenticates and sends a post request to the https://usb-api.mimecast.com/api/ttp/url/get-logs.
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
            "scanResult" = "malicious"

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
```

* Finally the log(s) are sent to the webhook URL and if this suceeds then the script outputs a success message. If the condition that the for loop is in returns false, meaning no data was found from the api, then the script returns a no data found message.

### Reference Links ###
* [Authentication and Headers](https://integrations.mimecast.com/documentation/api-overview/authentication-scripts-server-apps/)
* [Endpoint guide and example](https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-ttp-url-logs/)
