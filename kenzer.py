#imports
import zulip
import time
import os
import sys
from chatterbot import ChatBot
from chatterbot.trainers import ChatterBotCorpusTrainer
from configparser import ConfigParser

#core modules
from modules import enumerator
from modules import scanner

#colors
BLUE='\033[94m'
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CLEAR='\x1b[0m'

#configs
try:
    conf = "configs/kenzer.conf"
    config = ConfigParser()
    with open(conf) as f:
         config.read_file(f, conf)
    _BotMail=config.get("zulip", "email")
    _Site=config.get("zulip", "site")
    _APIKey=config.get("zulip", "key")
    _uploads=config.get("zulip", "uploads")
    _subscribe=config.get("zulip", "subscribe")
    _kenzer=config.get("env", "kenzer")
    _kenzerdb=config.get("env", "kenzerdb")
    _home=config.get("env", "home")
    _github=config.get("env", "github")
    os.chdir(_kenzer)
    os.environ["HOME"] = _home
    if(os.path.exists(_kenzerdb) == False):
        os.system("mkdir "+_kenzerdb)
except:
    sys.exit(RED+"[!] invalid configurations"+CLEAR)

#kenzer 
class Kenzer(object):
    
    #initializations
    def __init__(self):
        print(BLUE+"KENZER[2.1] by glatisant"+CLEAR)
        print(YELLOW+"automated web assets enumeration & scanning"+CLEAR)
        self.client = zulip.Client(email=_BotMail, site=_Site, api_key=_APIKey)
        self.upload=False
        if _subscribe=="True":
            self.subscribe()
            print(YELLOW+"[*] subscribed all streams"+CLEAR)    
        if _uploads=="True":
            self.upload=True
            print(YELLOW+"[*] enabled uploads"+CLEAR)
        print(YELLOW+"[*] training chatterbot"+CLEAR)
        self.chatbot = ChatBot("Kenzer")
        self.trainer = ChatterBotCorpusTrainer(self.chatbot)
        self.trainer.train("chatterbot.corpus.english")    
        self.modules=["subenum", "webenum", "portenum", "asnenum", "urlenum", "favscan", "idscan", "subscan", "cvescan", "vulnscan", "portscan", "parascan", "endscan", "buckscan", "enum", "scan", "recon", "hunt", "remlog"]
        print(YELLOW+"[*] KENZER is online"+CLEAR)
        print(YELLOW+"[*] {0} modules up & running".format(len(self.modules))+CLEAR)

    #subscribes to all streams
    def subscribe(self):
        try:
            json=self.client.get_streams()["streams"]
            streams=[{"name":stream["name"]} for stream in json]
            self.client.add_subscriptions(streams)
        except:
            print(RED+"[!] an exception occurred.... retrying...."+CLEAR)
            self.subscribe()

    #manual
    def man(self):
        message = "**KENZER[2.2]**\n"
        message +="**KENZER modules**\n"
        message +="  `subenum` - enumerates subdomains\n"
        message +="  `webenum` - enumerates webservers\n"
        message +="  `portenum` - enumerates open ports\n"
        message +="  `asnenum` - enumerates asn\n"
        message +="  `urlenum` - enumerates urls\n"
        message +="  `subscan` - hunts for subdomain takeovers\n"
        message +="  `cvescan` - hunts for CVEs\n"
        message +="  `vulnscan` - hunts for other common vulnerabilites\n"
        message +="  `portscan` - scans open ports\n"
        message +="  `parascan` - hunts for vulnerable parameters\n"
        message +="  `endscan` - hunts for vulnerable endpoints\n"
        message +="  `buckscan` - hunts for unreferenced aws s3 buckets\n"
        message +="  `favscan` - fingerprints webservers using favicon\n"
        message +="  `idscan` - identifies applications running on webservers\n"
        message +="  `enum` - runs all enumerator modules\n"
        message +="  `scan` - runs all scanner modules\n"
        message +="  `recon` - runs all modules\n"
        message +="  `hunt` - runs your custom workflow\n"
        message +="  `remlog` - removes log files\n"
        message +="  `upload` - switches upload functionality\n"
        message +="`kenzer <module>` - runs a specific modules\n"
        message +="`kenzer man` - shows this manual\n"
        message +="`kenzer man <module>` - shows manual for a specific module\n"
        message +="or you can just interact with chatterbot\n"
        self.sendMessage(message)
        return
    
    #modules manual
    def manModule(self, module):
        if module == "subenum":
            message ="`kenzer subenum <domain>` - enumerates subdomains of the given domain\n"
        elif module == "webenum":
            message ="`kenzer webenum <domain>` - probes web servers for enumerated subdomains of the given domain\n"
        elif module == "portenum":
            message ="`kenzer portenum <domain>` - enumerates open ports for enumerated subdomains of the given domain\n"
        elif module == "asnenum":
            message ="`kenzer asnenum <domain>` - enumerates asn for enumerated subdomains of the given domain\n"
        elif module == "urlenum":
            message ="`kenzer urlenum <domain>` - enumerates urls of the given domain\n"
        elif module == "subscan":
            message ="`kenzer subscan <domain>` - hunts for subdomain takeover possibilites of the given domain\n"
        elif module == "cvescan":
            message ="`kenzer cvescan <domain>` - checks if subdomains of the given domain are vulnerable to known CVEs\n"
        elif module == "vulnscan":
            message ="`kenzer vulnscan <domain>` - checks if subdomains of the given domain are vulnerable to any kind of vulnerabilities\n"
        elif module == "portscan":
            message ="`kenzer portscan <domain>` - scans & fingerprints open ports of the given domain\n"
        elif module == "parascan":
            message ="`kenzer parascan <domain>` - checks if parameters in the urls of the given domain are vulnerable to any kind of vulnerabilities\n"
        elif module == "endscan":
            message ="`kenzer endscan <domain>` - checks if endpoints of the given domain are vulnerable to any kind of vulnerabilities or known CVEs\n"
        elif module == "buckscan":
            message ="`kenzer buckscan <domain>` - hunts for unreferenced aws s3 buckets of the given domain \n"
        elif module == "favscan":
            message ="`kenzer favscan <domain>` - fingerprints webservers using favicon\n"
        elif module == "idscan":
            message ="`kenzer idscan <domain>` - identifies applications running on webservers\n"
        elif module == "enum":
            message ="`kenzer enum <domain>` - runs all enumerator modules on given domain\n"
        elif module == "scan":
            message ="`kenzer scan <domain>` - runs all scanner modules on given domain\n"
        elif module == "hunt":
            message ="`kenzer hunt <domain>` - runs your custom workflow on given domain\n"
        elif module == "recon":
            message ="`kenzer recon <domain>` - runs all modules on given domain\n"
        elif module == "remlog":
            message ="`kenzer remlog <domain>` - removes log files & empty files for given domain\n"
        elif module == "upload":
            message ="`kenzer upload` - turns upload on/off\n"
        else:
            message ="invalid module....\n"
        self.sendMessage(message)
        return

    #sends messages
    def sendMessage(self, message):
        time.sleep(2)
        if self.type == "private":
            self.client.send_message({
                "type": self.type,
                "to": self.sender_email,
                "content": message
            })
        else:
            self.client.send_message({
                "type": self.type,
                "subject": self.subject,
                "to": self.display_recipient,
                "content": message
            })
        time.sleep(3)
        return

    #uploads output
    def uploader(self, domain, raw):
        global _kenzerdb
        global _Site
        org=domain.replace(".","")
        data = _kenzerdb+org+"/"+raw
        print(data)
        if(os.path.exists(data) == False):
            return
        with open(data, 'rb') as fp:
            uploaded = self.client.call_endpoint(
            'user_uploads',
            method='POST',
            files=[fp],
        )
        self.sendMessage("{0}/{1} : {3}{2}".format(org, raw, uploaded['uri'], _Site))
        print(uploaded)

    #enumerates subdomains
    def subenum(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started subenum for: "+self.content[i].lower())
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb, _kenzer, _github)
            message = self.enum.subenum()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "subenum.kenz")
        return

    #probes web servers from enumerated subdomains
    def webenum(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started webenum for: "+self.content[i].lower())
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.enum.webenum()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "webenum.kenz")
        return
    
    #enumerates asn for enumerated subdomains
    def asnenum(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started asnenum for: "+self.content[i].lower())
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.enum.asnenum()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "asnenum.kenz")
        return
    
    #enumerates open ports
    def portenum(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started portenum for: "+self.content[i].lower())
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.enum.portenum()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "portenum.kenz")
        return
    #enumerates urls
    def urlenum(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started urlenum for: "+self.content[i].lower())
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb, _kenzer, _github)
            message = self.enum.urlenum()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "urlenum.kenz")
        return

    #hunts for subdomain takeovers
    def subscan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started subscan for: "+self.content[i].lower())
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.subscan()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "subscan.kenz")
        return

    #hunts for CVEs
    def cvescan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started cvescan for: "+self.content[i].lower())
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.cvescan()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "cvescan.kenz")
        return
    
    #hunts for other common vulnerabilities
    def vulnscan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started vulnscan for: "+self.content[i].lower())
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.vulnscan()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "vulnscan.kenz")
        return
    #scans open ports
    def portscan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started portscan for: "+self.content[i].lower())
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.portscan()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "portscan.kenz")
        return
    
    #hunts for vulnerable parameters
    def parascan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started parascan for: "+self.content[i].lower())
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.parascan()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "parascan.kenz")
        return
    
    #hunts for vulnerable endpoints
    def endscan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started endscan for: "+self.content[i].lower())
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.endscan()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "endscan.kenz")
        return
    
    #hunts for subdomain takeovers
    def buckscan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started buckscan for: "+self.content[i].lower())
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.buckscan()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "buckscan.kenz")
        return

    #fingerprints servers using favicons
    def favscan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started favscan for: "+self.content[i].lower())
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.favscan()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "favscan.kenz")
        return
    
    #identifies applications running on webservers
    def idscan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started idscan for: "+self.content[i].lower())
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.idscan()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "idscan.kenz")
        return

    #runs all enumeration modules
    def enum(self):
        self.subenum()
        self.webenum()
        self.portenum()
        self.asnenum()
        self.urlenum()
        return

    #runs all scanning modules
    def scan(self):
        self.favscan()
        self.idscan()
        self.subscan()
        self.portscan()
        self.buckscan()
        self.cvescan()
        self.vulnscan()
        self.parascan()
        self.endscan()
        return

    #define your custom workflow    
    def hunt(self):
        self.subenum()
        self.portenum()
        self.webenum()
        self.subscan()
        self.idscan()
        self.favscan()
        self.buckscan()
        self.portscan()
        self.cvescan()
        self.vulnscan()
        self.asnenum()
        self.urlenum()
        self.parascan()
        #self.endscan()
        #self.remlog()

    #runs all modules
    def recon(self):
        self.enum()
        self.scan()
        return

    #removes old log files
    def remlog(self):
        for i in range(2,len(self.content)):
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb)
            message = self.enum.remlog()
            self.sendMessage(message)
        return

    #controls
    def process(self, text):
        self.content = text["content"].split()
        self.sender_email = text["sender_email"]
        self.type = text["type"]
        self.display_recipient = text['display_recipient']
        self.subject = text['subject']
        content=self.content
        print(content)
        if self.sender_email == _BotMail:
            return
        if len(content)>1 and content[0].lower() == "kenzer" or content[0] == "@**kenzer**":
            if content[1].lower() == "man":
                if len(content)==2:
                    self.man()
                elif len(content)==3:
                    self.manModule(content[2])
                else:
                    message = "excuse me???"
                    self.sendMessage(message)    
            elif content[1].lower() == "subenum":
                self.subenum()
            elif content[1].lower() == "webenum":
                self.webenum()
            elif content[1].lower() == "asnenum":
                self.asnenum()
            elif content[1].lower() == "favscan":
                self.favscan()
            elif content[1].lower() == "portenum":
                self.portenum()
            elif content[1].lower() == "urlenum":
                self.urlenum()
            elif content[1].lower() == "subscan":
                self.subscan()
            elif content[1].lower() == "cvescan":
                self.cvescan()
            elif content[1].lower() == "vulnscan":
                self.vulnscan()
            elif content[1].lower() == "portscan":
                self.portscan()
            elif content[1].lower() == "parascan":
                self.parascan()
            elif content[1].lower() == "endscan":
                self.endscan()
            elif content[1].lower() == "idscan":
                self.idscan()
            elif content[1].lower() == "buckscan":
                self.buckscan()
            elif content[1].lower() == "enum":
                self.enum()
            elif content[1].lower() == "scan":
                self.scan()
            elif content[1].lower() == "hunt":
                self.hunt()
            elif content[1].lower() == "recon":
                self.recon()
            elif content[1].lower() == "remlog":
                self.remlog()
            elif content[1].lower() == "upload":
                self.upload = not self.upload
                self.sendMessage("upload: "+str(self.upload))
            else:
                message = "excuse me??"
                self.sendMessage(message)
        else:
            message = self.chatbot.get_response(' '.join(self.content))
            message = message.serialize()['text']
            self.sendMessage(message)
        return    

#main
def main():
    bot = Kenzer()
    bot.client.call_on_each_message(bot.process)

#runs main
if __name__ == "__main__":
    main()
