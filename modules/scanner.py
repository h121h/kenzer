#imports
import os
import time

#scanner
class Scanner:
    
    #initializations
    def __init__(self, domain, db, kenzer):
        self.domain = domain
        self.organization = domain.replace(".","")
        self.path = db+self.organization
        self.resources = kenzer+"resources/"
        self.templates = self.resources+"kenzer-templates/"
        if(os.path.exists(self.path) == False):
            os.system("mkdir "+self.path)


    #helper modules

    #runs nuclei
    def nuclei(self, template, hosts, output):
        os.system("nuclei -pbar -retries 2 -bulk-size 40 -t {3}nuclei/{0} -v -timeout 7 -l {1} -o {2}".format(template, hosts, output, self.templates))
        return
    
    #runs jaeles
    def jaeles(self, template, hosts, output):
        os.system("jaeles scan --retry 2 --no-background -c 40 -s {3}jaeles/{0}/ --timeout 7 -U {1} -O {2} -v ".format(template, hosts, output, self.templates))
        return

    #core modules

    #hunts for subdomain takeovers using nuclei & dnsprobe
    def subscan(self):
        domain = self.domain
        path = self.path
        output = path+"/subscanWEB.log"
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs) == False):
            return("run webenum for: "+self.domain)
        self.nuclei("subscan/web", subs, output)
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("run subenum for: "+self.domain)
        output = path+"/subscanDNS.log"
        self.nuclei("subscan/dns/subdomain-takeover-dns.yaml", subs, output)
        output = path+"/subscanDNSWILD.log"
        self.nuclei("subscan/dns/subdomain-takeover-dns-wildcards.yaml", subs, output)
        out = path+"/subscan.kenz"
        os.system("cat {0}/subscan* > {1}".format(path, out))
        os.system("cat {0} | cut -d' ' -f 3 | dnsprobe -r CNAME -f simple -o {1}".format(out, path+"/dnsprobeCNAME.log"))
        os.system("cat {0} | cut -d' ' -f 3 | dnsprobe -r A -f simple -o {1}".format(out, path+"/dnsprobeA.log"))
        return("completed subscan for: "+domain) 

    #hunts for CVEs using nuclei & jaeles
    def cvescan(self):
        domain = self.domain
        path = self.path
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs) == False):
            return("run webenum for: "+self.domain)
        output = path+"/cvescanDOMN.log"
        self.nuclei("cvescan", subs, output)
        output = path+"/cvescanDOMJ.log"
        self.jaeles("cvescan", subs, output)
        out = path+"/cvescan.kenz"
        os.system("cat {0}/cvescan* > {1}".format(path, out))
        return("completed cvescan for: "+domain)

    #hunts for vulnerabilities using nuclei & jaeles
    def vulnscan(self):
        domain = self.domain
        path = self.path
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs) == False):
            return("run webenum for: "+self.domain)
        output = path+"/vulnscanDOMN.log"
        self.nuclei("vulnscan", subs, output)
        output = path+"/vulnscanDOMJ.log"
        self.jaeles("vulnscan", subs, output)
        out = path+"/vulnscan.kenz"
        os.system("cat {0}/vulnscan* > {1}".format(path, out))
        return("completed vulnscan for: "+domain)
    
    #hunts for vulnerabilities & CVEs in endpoints using nuclei & jaeles
    def endscan(self):
        domain = self.domain
        path = self.path
        subs = path+"/endpoints.kenz"
        if(os.path.exists(subs) == False):
            return("no endpoints found for: "+self.domain)        
        output = path+"/endscanVULN.log"
        self.nuclei("vulnscan", subs, output)
        output = path+"/endscanCVEN.log"
        self.nuclei("cvescan", subs, output)
        output = path+"/endscanVULJ.log"
        self.jaeles("vulnscan", subs, output)
        output = path+"/endscanCVEJ.log"
        self.jaeles("cvescan", subs, output)
        out = path+"/endscan.kenz"
        os.system("cat {0}/endscan* > {1}".format(path, out))
        return("completed endscan for: "+domain)
    

    #hunts for vulnerabilities in URLs with parameters using nuclei & jaeles
    def parascan(self):
        domain = self.domain
        path = self.path
        subs = path+"/urlenum.kenz"
        if(os.path.exists(subs) == False):
            return("run urlenum for: "+self.domain)
        params = path+"/params.log"
        os.system("cat {0} | gf params > {1}".format(subs, params))
        output = path+"/parascanN.log"
        self.nuclei("parascan", params, output)
        output = path+"/parascanJ.log"
        self.jaeles("parascan", params, output)
        out = path+"/parascan.kenz"
        os.system("cat {0}/parascan* > {1}".format(path, out))
        return("completed parascan for: "+domain)

    #hunts for unreferenced aws s3 buckets using S3Hunter
    def buckscan(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("run subenum for: "+self.domain)
        output = path+"/s3huntDirect.log"
        os.system("S3Hunter -l {0} -t 10  -T 60 -o {1} --only-direct".format(subs, output))
        output = path+"/iperms.log"
        os.system("S3Hunter --no-regions -l {0} -o {1} -P".format(subs, output))
        subs = output
        output = path+"/s3huntPerms.log"
        self.nuclei("subscan/web/S3Hunter.yaml", subs, output)
        out = path+"/buckscan.kenz"
        os.system("cat {0}/s3hunt* | sort -u > {1}".format(path, out))
        return("completed buckscan for: "+domain)
    
    #fingerprints probed servers using favinizer
    def favscan(self):
        domain = self.domain
        path = self.path
        out = path+"/favscan.kenz"
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs) == False):
            return("run webenum for: "+self.domain)
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("favinizer -d {2}/favinizer.yaml -t 10 -T 60 -l {0} -o {1}".format(subs, out, self.templates))
        return("completed favinizer for: "+domain) 
    
    #fingerprints probed servers using nuclei
    def idscan(self):
        domain = self.domain
        path = self.path
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs) == False):
            return("run webenum for: "+self.domain)
        output = path+"/idscan.kenz"
        self.nuclei("idscan", subs, output)
        return("completed idscan for: "+domain)
    
    
    #scans open ports using NXScan
    def portscan(self):
        domain = self.domain
        path = self.path
        out = path+"/portscan.kenz"
        subs = path+"/portenum.kenz"
        if(os.path.exists(subs) == False):
            return("run portenum for: "+self.domain)
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("sudo NXScan --only-scan -l {0} -o {1} -T {2}/nmap-bootstrap.xsl".format(subs,path+"/nxscan",self.templates))
        os.system("cp {0}/scan.html {1}".format(path+"/nxscan",out))
        return("completed portscan for: "+domain) 
    
