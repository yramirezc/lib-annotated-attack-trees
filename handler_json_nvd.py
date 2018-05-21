import os
import json

class HandlerCVEJson:
    
    def __init__(self, path, years):
        
        """
        The original implementation considered a single json file.
        Now it considers a folder containing a file for each year (which can be several from 2002 to 2017)
        """
        max_year = max(years)
        jfl = open(os.path.join(path, 'nvdcve-1.0-' + str(max_year) + '.json'), 'rt')
        self.jsonDict = json.load(jfl)
        jfl.close()
        
        for yr in reversed(years):
            if yr != max_year:
                jfl = open(os.path.join(path, 'nvdcve-1.0-' + str(yr) + '.json'), 'rt')
                partial = json.load(jfl)
                jfl.close()
                self.jsonDict['CVE_Items'] += partial['CVE_Items']
        self.ordXCVEId = {}
        i = 0
        for cveInfo in self.jsonDict['CVE_Items']:
            self.ordXCVEId[cveInfo['cve']['CVE_data_meta']['ID']] = i
            i += 1
        
    def getCVEDescrOrd(self, order):
        return self.jsonDict['CVE_Items'][order]['cve']['description']['description_data'][0]['value']
    
    def getCVEDescrID(self, cveID):
        if cveID in self.ordXCVEId:
            return self.getCVEDescrOrd(self.ordXCVEId[cveID])
        else:
            return ''

    def getTokensCVEDescrOrd(self, order):
        return self.getCVEDescrOrd(self, order).split()
    
    def getTokensCVEDescrID(self, cveID):
        return self.getCVEDescrID(self, cveID).split()
    
    def countCVEDescr(self):
        return len(self.ordXCVEId)
    
    def getID(self, order):
        return self.jsonDict['CVE_Items'][order]['cve']['CVE_data_meta']['ID']
    
    def getAffectsInfo(self, order):
        info_items = []
        for vendor_data_item in self.jsonDict['CVE_Items'][order]['cve']['affects']['vendor']['vendor_data']:
            vname = vendor_data_item['vendor_name']
            for product in vendor_data_item['product']['product_data']:
                pname = product['product_name']
                for version in product['version']['version_data']:
                    vvalue = version['version_value']
                    info_items.append((vname, pname, vvalue))
        return info_items
    

    
    