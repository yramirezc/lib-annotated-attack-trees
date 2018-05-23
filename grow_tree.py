# Implementation of the tree enriching method 

import sys
import re
from pyswip import Prolog

prolog_interface = Prolog()   # Creating the prolog interface. It still has no knowledge.

class AnnotatedAttackTreeParser:
    
    def __init__(self):
        self.tokenizer = re.compile(r'[Oo][Rr]|[An][Nn][Dd]|\(|\)|,|".*?"|[A-Za-z_][A-Za-z0-9_]*')
        
    def get_tree(self, term):
        self.tokens = re.findall(self.tokenizer, term.strip())
        self.nextTok = 0
        try:
            return self.parse()
        except:
            return None 

    def parse(self):
        if self.tokens[self.nextTok].lower() == '(':
            self.nextTok += 1
            if self.tokens[self.nextTok][0] == '"' and self.tokens[self.nextTok][-1] == '"':
                assumptions = self.tokens[self.nextTok].strip('"')
                self.nextTok += 1
                if self.tokens[self.nextTok] == ',':
                    self.nextTok += 1
                    if self.tokens[self.nextTok][0] == '"' and self.tokens[self.nextTok][-1] == '"':
                        guarantees = self.tokens[self.nextTok].strip('"')
                        self.nextTok += 1
                        if self.tokens[self.nextTok] == ',':
                            self.nextTok += 1
                            if self.tokens[self.nextTok].lower() == 'or':
                                self.nextTok += 1
                                if self.tokens[self.nextTok] == '(':
                                    self.nextTok += 1
                                    children = self.parse_subtrees()
                                    if self.tokens[self.nextTok] == ')':
                                        self.nextTok += 1
                                        if self.tokens[self.nextTok] == ')':
                                            self.nextTok += 1
                                            return {"assumptions" : assumptions, "guarantees" : guarantees, "type" : "or", "children" : children}
                                        else:
                                            raise 'Syntax error'
                                    else:
                                        raise 'Syntax error'
                                else:
                                    raise 'Syntax error'
                            elif self.tokens[self.nextTok].lower() == 'and':
                                self.nextTok += 1
                                if self.tokens[self.nextTok] == '(':
                                    self.nextTok += 1
                                    children = self.parse_subtrees()
                                    if self.tokens[self.nextTok] == ')':
                                        self.nextTok += 1
                                        if self.tokens[self.nextTok] == ')':
                                            self.nextTok += 1
                                            return {"assumptions" : assumptions, "guarantees" : guarantees, "type" : "and", "children" : children}
                                        else:
                                            raise 'Syntax error'
                                    else:
                                        raise 'Syntax error'
                                else:
                                    raise 'Syntax error'
                            elif self.found_basic_action():
                                label = self.tokens[self.nextTok]
                                self.nextTok += 1
                                if self.tokens[self.nextTok] == ')':
                                    self.nextTok += 1
                                    return {"assumptions" : assumptions, "guarantees" : guarantees, "type" : "leaf", "label" : label,  "children" : []}
                                else:
                                    raise 'Syntax error'
                            else:
                                raise 'Syntax error'
                        else:
                            raise 'Syntax error'
                    else:
                        raise 'Syntax error'
                else:
                    raise 'Syntax error'
            else:
                raise 'Syntax error'
        else:
            raise 'Syntax error'
    
    def parse_subtrees(self):
        if self.tokens[self.nextTok].lower() == '(':
            return [self.parse()] + self.parse_remaining_subtrees()
        else:
            raise 'Syntax error'
            
    def parse_remaining_subtrees(self):
        if self.tokens[self.nextTok] == ',':
            self.nextTok += 1
            if self.tokens[self.nextTok].lower() == '(':
                return [self.parse()] + self.parse_remaining_subtrees()
            else:
                raise 'Syntax error'
        else:   # Empty string accepted
            return []
    
    def found_basic_action(self):
        if self.tokens[self.nextTok].lower() == 'or':
            return False
        elif self.tokens[self.nextTok].lower() == 'and':
            return False
        else: 
            return re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', self.tokens[self.nextTok])

def refine(atree, cve):
    added = False
    if atree['type'] == 'leaf':
        ret_run_att = evaluate_attachable_predicate(atree['assumptions'], atree['guarantees'], cve)
        if ret_run_att[0]:
            atree['type'] = 'or'
            atree['children'] = [{"assumptions" : ret_run_att[1], "guarantees" : ret_run_att[2], "type" : "newly_attached_leaf", "label" : cve, "children" : []}]
            added = True
    elif atree['type'] == 'or':
        child_refined = False
        for child in atree['children']:
            child_refined = child_refined or refine(child, cve)
        if child_refined:
            added = True
        else:
            ret_run_att = evaluate_attachable_predicate(atree['assumptions'], atree['guarantees'], cve)
            if ret_run_att[0]:
                atree['children'].append({"assumptions" : ret_run_att[1], "guarantees" : ret_run_att[2], "type" : "newly_attached_leaf", "label" : cve, "children" : []})
                added = True
    elif atree['type'] == 'and':
        for child in atree['children']:
            if refine(child, cve):
                added = True
    #else:   # atree['type'] == 'newly_attached_leaf'. New attachments here will only be allowed when the tree is consolidated   
    return added

def evaluate_attachable_predicate(assumptions, guarantees, cve):
    query_results = prolog_interface.query('attachable(CVE,' + assumptions + ',' + guarantees +')')
    attachable_cves = set(qres['CVE'] for qres in query_results)
    if cve in attachable_cves:
        return [True, "", ""]   # [predicate response, assumptions new subtree, guarantees new subtree]. To be completed
    else:
        return [False, "", ""]   # [predicate response, assumptions new subtree, guarantees new subtree]

def consolidate_enriched_tree(atree):
    if atree['type'] in ['or', 'and']:
        for child in atree['children']:
            consolidate_enriched_tree(child)        
    elif atree['type'] == 'newly_attached_leaf':
        atree['type'] = 'leaf'

def aatree_as_str(atree):
    if atree['type'] in ['leaf', 'newly_attached_leaf']:
        if 'label' in atree:
            return '("' + atree['assumptions'] + '","' + atree['guarantees'] + '",' + atree['label'] + ')'
        else:
            return '("' + atree['assumptions'] + '","' + atree['guarantees'] + '",bx)'
    elif atree['type'] == 'or':
        return '("' + atree['assumptions'] + '","' + atree['guarantees'] + '",OR(' + ','.join(aatree_as_str(child) for child in atree['children']) + '))'
    else:   # atree['type'] == 'and':
        return '("' + atree['assumptions'] + '","' + atree['guarantees'] + '",AND(' + ','.join(aatree_as_str(child) for child in atree['children']) + '))'

# sys.argv[1]: File containing annotated attack trees, one per line
# sys.argv[2]: File containing list of CVEs in use
# sys.argv[3]: Path of the file assumptionsKbAuto.pl
# sys.argv[4]: Path of the file guaranteesKbAuto.pl
# sys.argv[5]: Path of the file rulesFactsManual.pl 
# sys.argv[6]: Output file

if len(sys.argv) == 7:
    
    # Load knowledge base. All facts and rules in assumptionsKbAuto.pl, guaranteesKbAuto.pl and rulesFactsManual.pl
    # are read from the files and asserted into the working prolog_interface environment in run-time. This SHOULD NOT be necessary, 
    # but the <consult> method provided in PySWIP is not behaving as described in the documentation: it seems to always
    # fail to access the given file.    
    
    print 'Loading knowledge base'
    
    #prolog_interface.consult(sys.args[3])
    #prolog_interface.consult("guaranteesKbAuto.pl")
    #prolog_interface.consult("rulesFactsManual.pl")
    
    lns = open(sys.argv[3], 'rt').readlines()
    for ln in lns:
        sln = ln.strip()
        if len(sln) > 0 and sln[-1] == '.':
            slnnp = sln.strip('.')
            prolog_interface.assertz(slnnp)
            
    lns = open(sys.argv[4], 'rt').readlines()
    for ln in lns:
        sln = ln.strip()
        if len(sln) > 0 and sln[-1] == '.':
            slnnp = sln.strip('.')
            prolog_interface.assertz(slnnp)
    
    lns = open(sys.argv[5], 'rt').readlines()
    for ln in lns:
        sln = ln.strip()
        if len(sln) > 0 and sln[-1] == '.' and ':- [' not in sln:
            slnnp = sln.strip('.')
            if ':-' in slnnp:
                slnnp = '(' + slnnp + ')'
            prolog_interface.assertz(slnnp)
    
    print 'Done loading'
    
#     # Test 1: querying for numbers
#     qresults = prolog_interface.query('countAttachable([[cisco]],[[[remote,attacker],execute,[arbitrary,command]]],X)')
#     for qres in qresults:
#         if 'X' in qres:
#             print 'Query result: ' + str(qres['X'])
#      
#     # Test 2: querying for a list of alphanumericals
#     qresults = prolog_interface.query('attachable(CVE,[[cisco]],[[[remote,attacker],execute,[arbitrary,command]]])')
#     attachable_cves = set(qres['CVE'] for qres in qresults) 
#     print 'Query result: ' + ', '.join(attachable_cves)
    
    cves = (' '.join(ln.strip() for ln in open(sys.argv[2], 'rt').readlines())).split()
     
    lns = open(sys.argv[1], 'rt').readlines()
    outf = open(sys.argv[3], 'wt')
     
    for ln in lns:
        atree = AnnotatedAttackTreeParser().get_tree(ln.strip())
        if atree is not None:
            print aatree_as_str(atree)
            for cve in cves:
                refine(atree, cve)
            consolidate_enriched_tree(atree)
            outf.write(aatree_as_str(atree)) 
     
    outf.close()
    

