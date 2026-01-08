from dataclasses import dataclass
from typing import List, Optional

@dataclass
class TakeoverFingerprint:
    """Fingerprint for detecting vulnerable services"""

    service: str
    cnames: List[str]
    fingerprints: List[str]  # Response body patterns
    nxdomain: bool = False  # Vulnerable if NXDOMAIN
    http_status: Optional[int] = None  # Specific status code
    documentation: str = ""


# Fingerprints from can-i-take-over-xyz and other sources
FINGERPRINTS = [
    TakeoverFingerprint(
        service="AWS S3",
        cnames=[".s3.amazonaws.com", ".s3-website", ".s3.", ".amazonaws.com/"],
        fingerprints=["NoSuchBucket", "The specified bucket does not exist"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#amazon-s3",
    ),
    TakeoverFingerprint(
        service="GitHub Pages",
        cnames=[".github.io", ".githubusercontent.com"],
        fingerprints=[
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/)",
        ],
        http_status=404,
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#github-pages",
    ),
    TakeoverFingerprint(
        service="Heroku",
        cnames=[".herokudns.com", ".herokuapp.com", ".herokussl.com"],
        fingerprints=[
            "No such app",
            "no-such-app",
            "herokucdn.com/error-pages/no-such-app",
        ],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#heroku",
    ),
    TakeoverFingerprint(
        service="Azure",
        cnames=[
            ".azurewebsites.net",
            ".cloudapp.net",
            ".cloudapp.azure.com",
            ".trafficmanager.net",
            ".blob.core.windows.net",
            ".azure-api.net",
            ".azurehdinsight.net",
            ".azureedge.net",
            ".azurecontainer.io",
        ],
        fingerprints=["404 Web Site not found", "Web App - Pair with a custom domain"],
        nxdomain=True,
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#azure",
    ),
    TakeoverFingerprint(
        service="Shopify",
        cnames=[".myshopify.com"],
        fingerprints=[
            "Sorry, this shop is currently unavailable",
            "Only one step left",
        ],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#shopify",
    ),
    TakeoverFingerprint(
        service="Fastly",
        cnames=[".fastly.net", ".fastlylb.net"],
        fingerprints=["Fastly error: unknown domain"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#fastly",
    ),
    TakeoverFingerprint(
        service="Pantheon",
        cnames=[".pantheonsite.io", ".pantheon.io"],
        fingerprints=["404 error unknown site", "The gods are wise"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#pantheon",
    ),
    TakeoverFingerprint(
        service="Tumblr",
        cnames=[".tumblr.com"],
        fingerprints=[
            "Whatever you were looking for doesn't currently exist at this address",
            "There's nothing here.",
        ],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#tumblr",
    ),
    TakeoverFingerprint(
        service="WordPress.com",
        cnames=[".wordpress.com"],
        fingerprints=["Do you want to register"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#wordpresscom",
    ),
    TakeoverFingerprint(
        service="Zendesk",
        cnames=[".zendesk.com", ".zopim.com"],
        fingerprints=["Help Center Closed", "this help center no longer exists"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#zendesk",
    ),
    TakeoverFingerprint(
        service="Unbounce",
        cnames=[".unbounce.com", "unbouncepages.com"],
        fingerprints=[
            "The requested URL was not found on this server",
            "The page you're looking",
        ],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#unbounce",
    ),
    TakeoverFingerprint(
        service="HelpScout",
        cnames=[".helpscoutdocs.com"],
        fingerprints=["No settings were found for this company"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#helpscout",
    ),
    TakeoverFingerprint(
        service="Ghost",
        cnames=[".ghost.io"],
        fingerprints=["The thing you were looking for is no longer here"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#ghost",
    ),
    TakeoverFingerprint(
        service="Surge.sh",
        cnames=[".surge.sh"],
        fingerprints=["project not found"],
        nxdomain=True,
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#surge",
    ),
    TakeoverFingerprint(
        service="Bitbucket",
        cnames=[".bitbucket.io", ".bitbucket.org"],
        fingerprints=["Repository not found"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#bitbucket",
    ),
    TakeoverFingerprint(
        service="UserVoice",
        cnames=[".uservoice.com"],
        fingerprints=["This UserVoice subdomain is currently available"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#uservoice",
    ),
    TakeoverFingerprint(
        service="Intercom",
        cnames=[".custom.intercom.help"],
        fingerprints=[
            "This page is reserved for a Intercom",
            "Uh oh. That page doesn't exist",
        ],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#intercom",
    ),
    TakeoverFingerprint(
        service="Webflow",
        cnames=[".webflow.io", "proxy.webflow.com", "proxy-ssl.webflow.com"],
        fingerprints=["The page you are looking for doesn't exist or has been moved"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#webflow",
    ),
    TakeoverFingerprint(
        service="Kajabi",
        cnames=[".mykajabi.com", ".kajabi.com"],
        fingerprints=["The page you were looking for doesn't exist"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#kajabi",
    ),
    TakeoverFingerprint(
        service="Thinkific",
        cnames=[".thinkific.com"],
        fingerprints=["You may have mistyped the address or the page may have moved"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#thinkific",
    ),
    TakeoverFingerprint(
        service="Tave",
        cnames=[".clientaccess.tave.com"],
        fingerprints=["<h1>Error 404: Page Not Found</h1>"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#tave",
    ),
    TakeoverFingerprint(
        service="Wishpond",
        cnames=[".wishpond.com"],
        fingerprints=["https://www.wishpond.com/404?campaign=true"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#wishpond",
    ),
    TakeoverFingerprint(
        service="Aftership",
        cnames=[".aftership.com"],
        fingerprints=['Oops.</h2><p class="text-muted text-tight">The page'],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#aftership",
    ),
    TakeoverFingerprint(
        service="Aha!",
        cnames=[".ideas.aha.io"],
        fingerprints=["There is no portal here ... sending you back to Aha!"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#aha",
    ),
    TakeoverFingerprint(
        service="Brightcove",
        cnames=[".bcvp0rtal.com", ".brightcovegallery.com", ".gallery.video"],
        fingerprints=['<p class="bc-gallery-error-code">Error Code: 404</p>'],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#brightcove",
    ),
    TakeoverFingerprint(
        service="Campaign Monitor",
        cnames=[".createsend.com", ".name.createsend.com"],
        fingerprints=["Trying to access your account?", "Double check the URL"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#campaign-monitor",
    ),
    TakeoverFingerprint(
        service="Canny",
        cnames=[".canny.io"],
        fingerprints=["Company Not Found", "There is no such company"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#canny",
    ),
    TakeoverFingerprint(
        service="Cargo",
        cnames=[".cargocollective.com"],
        fingerprints=["<title>404 &mdash; File not found</title>"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#cargo",
    ),
    TakeoverFingerprint(
        service="Fly.io",
        cnames=[".fly.dev"],
        fingerprints=["404 Not Found"],
        nxdomain=True,
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#flyio",
    ),
    TakeoverFingerprint(
        service="Frontify",
        cnames=[".frontify.com"],
        fingerprints=["404 - Page Not Found", "Oops… looks like you got lost"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#frontify",
    ),
    TakeoverFingerprint(
        service="GetResponse",
        cnames=[".gr8.com"],
        fingerprints=[
            "With GetResponse Landing Pages, lead generation has never been easier"
        ],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#getresponse",
    ),
    TakeoverFingerprint(
        service="HelpJuice",
        cnames=[".helpjuice.com"],
        fingerprints=["We could not find what you're looking for"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#helpjuice",
    ),
    TakeoverFingerprint(
        service="HelpRace",
        cnames=[".helprace.com"],
        fingerprints=["Alias not configured!", "Admin of this Helprace account"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#helprace",
    ),
    TakeoverFingerprint(
        service="JetBrains YouTrack",
        cnames=[".myjetbrains.com"],
        fingerprints=["is not a registered InCloud YouTrack"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#jetbrains",
    ),
    TakeoverFingerprint(
        service="Kinsta",
        cnames=[".kinsta.cloud"],
        fingerprints=["No Site For Domain"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#kinsta",
    ),
    TakeoverFingerprint(
        service="LaunchRock",
        cnames=[".launchrock.com"],
        fingerprints=["It looks like you may have taken a wrong turn somewhere"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#launchrock",
    ),
    TakeoverFingerprint(
        service="Netlify",
        cnames=[".netlify.app", ".netlify.com", ".bitballoon.com"],
        fingerprints=["Not Found - Request ID:"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#netlify",
    ),
    TakeoverFingerprint(
        service="Ngrok",
        cnames=[".ngrok.io"],
        fingerprints=["ngrok.io not found", "Tunnel .*.ngrok.io not found"],
        nxdomain=True,
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#ngrok",
    ),
    TakeoverFingerprint(
        service="Pingdom",
        cnames=[".stats.pingdom.com"],
        fingerprints=[
            "Public Report Not Activated",
            "This public report page has not been activated",
        ],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#pingdom",
    ),
    TakeoverFingerprint(
        service="Readme.io",
        cnames=[".readme.io"],
        fingerprints=["Project doesnt exist... yet!"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#readmeio",
    ),
    TakeoverFingerprint(
        service="Short.io",
        cnames=[".short.io"],
        fingerprints=["Link does not exist"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#shortio",
    ),
    TakeoverFingerprint(
        service="SmartJobBoard",
        cnames=[".smartjobboard.com"],
        fingerprints=[
            "This job board website is either expired or its domain name is invalid"
        ],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#smartjobboard",
    ),
    TakeoverFingerprint(
        service="Strikingly",
        cnames=[".s.strikinglydns.com", ".strikinglydns.com"],
        fingerprints=[
            "page not found",
            "But if you're looking to build your own website",
        ],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#strikingly",
    ),
    TakeoverFingerprint(
        service="Tilda",
        cnames=[".tilda.ws"],
        fingerprints=["Domain has been assigned", "Please go to"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#tilda",
    ),
    TakeoverFingerprint(
        service="Uberflip",
        cnames=[".uberflip.com"],
        fingerprints=["Non-hub domain, The URL you've accessed does not provide a hub"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#uberflip",
    ),
    TakeoverFingerprint(
        service="Uptimerobot",
        cnames=[".stats.uptimerobot.com"],
        fingerprints=["page not found"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#uptimerobot",
    ),
    TakeoverFingerprint(
        service="Vercel",
        cnames=[".vercel.app", ".now.sh", ".zeit.co"],
        fingerprints=["The deployment could not be found on Vercel"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#vercel",
    ),
    TakeoverFingerprint(
        service="WIX",
        cnames=[".wixsite.com", ".wix.com"],
        fingerprints=[
            "Error ConnectYourDomain occurred",
            "Looks Like This Domain Isn't Connected",
        ],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#wix",
    ),
    TakeoverFingerprint(
        service="Worksites",
        cnames=[".worksites.net"],
        fingerprints=[
            "Hello! Sorry, but the website you&rsquo;re looking for doesn't exist."
        ],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#worksites",
    ),
    TakeoverFingerprint(
        service="Agile CRM",
        cnames=[".agilecrm.com"],
        fingerprints=["Sorry, this page is no longer available"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#agile-crm",
    ),
    TakeoverFingerprint(
        service="Anima",
        cnames=[".animaapp.io"],
        fingerprints=[
            "The page you're looking for doesn't exist",
            "If you think this is a mistake",
        ],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#anima",
    ),
    TakeoverFingerprint(
        service="Announcekit",
        cnames=[".announcekit.app"],
        fingerprints=["Error 404 - AnnounceKit"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#announcekit",
    ),
    TakeoverFingerprint(
        service="BigCartel",
        cnames=[".bigcartel.com"],
        fingerprints=["<h1>Oops! We couldn&#8217;t find that page.</h1>"],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#bigcartel",
    ),
    TakeoverFingerprint(
        service="AWS Elastic Beanstalk",
        cnames=[".elasticbeanstalk.com"],
        fingerprints=["404 Not Found"],
        nxdomain=True,
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#aws-elastic-beanstalk",
    ),
    TakeoverFingerprint(
        service="AWS CloudFront",
        cnames=[".cloudfront.net"],
        fingerprints=[
            "Bad Request: ERROR: The request could not be satisfied",
            "ERROR: The request could not be satisfied",
        ],
        documentation="https://github.com/EdOverflow/can-i-take-over-xyz#amazon-cloudfront",
    ),
]
