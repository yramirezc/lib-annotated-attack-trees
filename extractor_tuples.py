# Implements the class TupleExtractor which automatically extracts the set of assumption and guarantee facts 
# from (a subset of) the NVD  

import sys
import os
from handler_json_nvd import HandlerCVEJson
import re
from handler_stanford_corenlp_xml_output import HandlerStanfordCoreNLPOutputXML

class TupleExtractor:
    
    def __init__(self, db_fldr, prs_fldr, stopwrd_fl, years):
        
        self.work_folder = db_fldr
        self.parser_folder = prs_fldr
        self.nvd_handler = HandlerCVEJson(db_fldr, years)
        
        if os.path.isfile(stopwrd_fl):
            self.stopwords = set(ln.strip() for ln in open(stopwrd_fl, 'rt').readlines())
        else:
            self.stopwords = set([])
        self.stopwords.add('')
            
    def do_extraction(self):
        self.extract_affected_envs_facts()
        self.extract_allowed_actions_facts()
    
    
    def extract_affected_envs_facts(self):
        ant_fact_set_fl = open(os.path.join(self.work_folder, 'facts-assumptions.txt'), 'wt')
        for i in range(0, self.nvd_handler.countCVEDescr()):
            affect_info_items = self.nvd_handler.getAffectsInfo(i)
            affect_info_items_no_version = set((item[0], item[1]) for item in affect_info_items)
            if len(affect_info_items) >= 1 or len(affect_info_items_no_version) >= 1:
                ant_fact_set_fl.write(self.nvd_handler.getID(i) + '|' + ' '.join('envPropertyMatches(' + ':'.join(item) + ')' for item in affect_info_items) + ' ' + ' '.join('envPropertyMatches(' + ':'.join(item) + ')' for item in affect_info_items_no_version) + '\n') 
        ant_fact_set_fl.close()
    
        
    def extract_allowed_actions_facts(self):
        
        cons_fact_set_fl = open(os.path.join(self.work_folder, 'facts-guarantees.txt'), 'wt') 
        
        for i in range(0, self.nvd_handler.countCVEDescr()):
            
            descr = self.nvd_handler.getCVEDescrOrd(i).lower()
            
            cons_fact_set_ln = self.nvd_handler.getID(i)
            
            useful_sent_found = False
            
            if re.search(r'allows?', descr) is not None or re.search(r'permits?', descr) is not None:   # We first check if the (possibly multi-sentence) description contains the terms
                
                corenlp_handler = HandlerStanfordCoreNLPOutputXML(os.path.join(self.parser_folder, self.nvd_handler.getID(i) + '.txt.xml'))
                
                for i in range(0, corenlp_handler.sentence_count()):   # We will use the sentence splitting made by Stanford CoreNLP
                    
                    allow_clause_heads = corenlp_handler.get_occurrences(i, [('allow','VB'), ('permit','VB')])   # Now we actually determine if the sentence contains the terms acting as verbs
                    
                    if len(allow_clause_heads) >= 1:
                    
                        cons_fact_set_ln += '|'
                        
                        for head in allow_clause_heads:
                        
                            agent_heads = corenlp_handler.get_dependents(i, ['dobj'], head)
                            action_vbs = corenlp_handler.get_dependents(i, ['xcomp'], head)
                            
                            for ah in agent_heads:
                                
                                agent_bow = self.clean_bow(corenlp_handler.get_noun_phrase_bow(i, ah[1]))
                                
                                if len(agent_bow) >= 1:
                                
                                    for av in action_vbs:
                                        
                                        effect_heads = corenlp_handler.get_dependents(i, ['dobj'], av[1])
                                        
                                        for eh in effect_heads:
                                            effect_bow = self.clean_bow(corenlp_handler.get_noun_phrase_bow(i, eh[1]))
                                            if len(effect_bow) >= 1:
                                                cons_fact_set_ln += 'allowedAction({' + ','.join(agent_bow) + '},' + corenlp_handler.get_lemma(i, av[1]) + ',{' + ','.join(effect_bow) + '}) '
                                                useful_sent_found = True 
            
            if useful_sent_found:
                cons_fact_set_fl.write(cons_fact_set_ln + '\n')
        
        cons_fact_set_fl.close()
    
    
    def clean_bow(self, bow):
        clbow = set([])
        for term in bow:
            if term not in self.stopwords and self.not_just_numbers(term):
                clbow.add(term)
        return clbow
    
    def not_just_numbers(self, term):
        for ch in term:
            if ch not in '-+0123456789':
                return True
        return False
        
# argv[2]: NVD folder
# argv[3]: parser output folder
# argv[4]: stopwords

extractor = TupleExtractor(sys.argv[2], sys.argv[3], sys.argv[4], range(2013,2018))
extractor.do_extraction()

