#imports
import os

#monitor
class Monitor:
    
    #initializations
    def __init__(self, domains, db):
        self.domain = domain
        self.organization = "monitor"
        self.path = db+self.organization
        if(os.path.exists(self.path) == False):
            os.system("mkdir "+self.path)

    #core monitor modules
    
    #enumerates subdomains using certex
    def certex(self):
        domains = self.domains
        path = self.path
        output = path+"/subenum.kenz"
        os.system("certex -d {0} -o {1} &".format(domains, output))
        return