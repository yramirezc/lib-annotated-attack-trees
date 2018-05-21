import xml.etree.ElementTree as et

class HandlerStanfordCoreNLPOutputXML:
    
    def __init__(self, xmlfl):
        
        self.xmltree = et.parse(xmlfl)
        self.root = self.xmltree.getroot()
        
    def sentence_count(self):
        return len(self.xmltree.getroot()[0][0])
    
    def get_words(self, sent_ord):
        root = self.xmltree.getroot()
        if sent_ord < len(root[0][0]):
            return list(token[0].text for token in root[0][0][sent_ord][0])
        else:
            return []
    
    def get_lemmas(self, sent_ord):
        root = self.xmltree.getroot()
        if sent_ord < len(root[0][0]):
            return list(token[1].text for token in root[0][0][sent_ord][0])
        else:
            return []
        
    def get_lemma(self, sent_ord, twid):
        tagged_words = self.get_tagged_words(sent_ord)
        if twid in tagged_words:
            return tagged_words[twid][1]
        else:
            return '<UNKNOWN>'
    
    def get_postags(self, sent_ord):
        root = self.xmltree.getroot()
        if sent_ord < len(root[0][0]):
            return list(token[4].text for token in root[0][0][sent_ord][0])
        else:
            return []
        
    def get_tagged_words(self, sent_ord):
        root = self.xmltree.getroot()
        if sent_ord < len(root[0][0]):
            return dict((token.attrib['id'], (token[0].text, token[1].text, token[4].text)) for token in root[0][0][sent_ord][0])
        else:
            return {}
        
    def get_occurrences(self, sent_ord, lemma_tag_pairs):
        occurrences = []
        tagged_words = self.get_tagged_words(sent_ord)
        for twid in tagged_words:
            for lt in lemma_tag_pairs:
                if tagged_words[twid][1] == lt[0] and tagged_words[twid][2].find(lt[1]) == 0:
                    occurrences.append(twid)
        return occurrences
    
    def get_dependencies(self, sent_ord, dep_types, lemmas):
        tagged_words = self.get_tagged_words(sent_ord)
        dependencies = self.xmltree.getroot()[0][0][sent_ord][6]   # We will use enhanced++ dependencies
        found_deps = []
        for twid in tagged_words:
            if tagged_words[twid][1] in lemmas:
                for dep in dependencies:  
                    if dep[0].attrib['idx'] == twid and dep.attrib['type'] in dep_types:
                        found_deps.append((dep.attrib['type'], tagged_words[twid][1], tagged_words[dep[1].attrib['idx']][1]))
        return found_deps
    
    def get_dependents(self, sent_ord, dep_types, twid):
        dependencies = self.xmltree.getroot()[0][0][sent_ord][6]   # We will use enhanced++ dependencies
        found_deps = []
        for dep in dependencies:  
            if dep[0].attrib['idx'] == twid and dep.attrib['type'] in dep_types:
                found_deps.append((dep.attrib['type'], dep[1].attrib['idx']))
        return found_deps
    
    def get_noun_phrase_bow(self, sent_ord, twid):
        twidset = set([twid])
        dependents = self.get_dependents(sent_ord, ['amod', 'compound', 'nmod:of'], twid)
        for dp in dependents:
            if dp[0] == 'amod':
                twidset.add(dp[1])
            else:
                twidset = twidset.union(self.extend_noun_phrase_twidset(sent_ord, dp[1]))
        tagged_words = self.get_tagged_words(sent_ord)
        return set(tagged_words[twi][1] for twi in twidset)   # Use lemmas
        
    def extend_noun_phrase_twidset(self, sent_ord, twid):
        twidset = set([twid])
        dependents = self.get_dependents(sent_ord, ['amod', 'compound'], twid)
        for dp in dependents:
            if dp[0] == 'amod':
                twidset.add(dp[1])
            else:
                twidset = twidset.union(self.extend_noun_phrase_twidset(sent_ord, dp[1]))
        return twidset
    
    def get_preceeding_proper_nouns(self, sent_ord, max_twid):
        proper_nouns = set([])
        tagged_words = self.get_tagged_words(sent_ord)
        for twid in tagged_words:
            if int(twid) < max_twid and tagged_words[twid][2] == 'NNP':
                proper_nouns.add(tagged_words[twid][0])
        return proper_nouns
