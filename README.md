# pylon

Pylon is an automagical reverse web proxy written in Go that handles authentication and HTTPS for you, thanks to Let's Encrypt and Google OAuth.
This is especially useful if you want to run several services on a homelab without setting up multiple nginx proxies and manually provisioning certificates or custom authentication methods.
This is a functioning project, but should be seen as a work in progress. There are many features in the works that don't exist in this version of the project.
If you would like to contribute, feel free to do so!


## Prerequisites:

1. You use a Gmail or otherwise "Google Account", such as a GSuite/Workspace account or Google Cloud Identity account.
    1. Google-based OAuth is not the only OAuth provider possible to secure this platform - many more could be added, such as Github or Facebook, but this was just the one i'm most familiar with to get the project going.
2. You own a domain name with DNS records that point to your network.
3. ??? please let me know if i'm missing something from your particular environment.


## Install:

1. Head to console.google.com. On the project selector page, click **Create Project** to begin creating a new Cloud project. Name it anything you want.
2. Go to the **APIs & Services > Credentials** page.
3. On the **Credentials** page, click **Create credentials > OAuth client ID**.
4. Select **Web application** under **Application type**
    1. Name the credentials whatever you'd like.
    2. Under **Authorized redirect URIs**, add `https://YOURDOMAIN.com/pylon/oauth2callback`, editing for your own domain.
5. Hit **Create** and take note of the resulting Client ID and Client Secret for the following steps.
    1. You may or may not need to configure a "consent screen" before you create your credentials. Follow the on-screen steps to do so.
6. Create a `config.json` in a place we can reference later (in our example, we'll use `~/pylon/config/`).  An example can be grabbed [here](https://github.com/zhardie/pylon/blob/main/example_config.json)
    1. Change `tldn` to your top level domain name, without the http protocol, for example, `example.com`
    2. Create a random phrase for `session_key`. This can be anything.
    3. Change `auth_url` and `redirect_url` to use your own domain name, but keep the existing paths (`pylon/auth`, `pylon/oauth2callback`), as in the example config.
    4. Paste your Client ID and Client Secret to `client_id` and `client_secret`, respectively, from step 5.
7. Fire up the proxy server with `docker run -d -v ~/pylon/certs:/certs -v ~/pylon/config:/config -p 80:80 -p 443:443 -p 3001:3001 zhardie/pylon:latest`
8. Set up your proxy by heading to http://localhost:3001 and adding an external subdomain (i.e. `https://foo.yourdomain.com`) and then where you'd like the request to end up internally (i.e. `http://192.168.1.69`)
    1. Authorization to each proxied service is defined by email address. To authorize someone's Google account to access your service, click the information menu ( i ) after each proxy definition and type each email address (i.e. you@gmail.com)
    2. External subdomains need to point to your proxy server. The easiest way to do this is just create CNAME records pointing to your top level domain name.
    3. Certificates will automatically be generated upon the first time visiting the external address for each proxy service and will be saved wherever you specified in the `docker run` command.
    4. When saving new users or proxy configurations on the dashboard, your `config.json` file will update and the proxy server will restart automatically.
