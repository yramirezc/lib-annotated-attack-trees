# Implementation of the tree enriching method 

import sys
import re

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
                        if self.tokens[self.nextTok].lower() == 'or':
                            self.nextTok += 1
                            if self.tokens[self.nextTok] == '(':
                                self.nextTok += 1
                                children = self.parse_subtrees()
                                if self.tokens[self.nextTok] == ')':
                                    self.nextTok += 1
                                    return {"assumptions" : assumptions, "guarantees" : guarantees, "type" : "or", "children" : children}
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
                                    return {"assumptions" : assumptions, "guarantees" : guarantees, "type" : "and", "children" : children}
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
    
    def parse_subtrees(self):
        if self.tokens[self.nextTok].lower() == 'or' or self.tokens[self.nextTok].lower() == 'and' or self.tokens[self.nextTok].lower() == '(':
            return [self.parse()] + self.parse_remaining_subtrees()
        else:
            raise 'Syntax error'
            
    def parse_remaining_subtrees(self):
        if self.tokens[self.nextTok] == ',':
            self.nextTok += 1
            if self.tokens[self.nextTok].lower() == 'or' or self.tokens[self.nextTok].lower() == 'and' or self.tokens[self.nextTok].lower() == '(':
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
    # TODO: Pipeline with SWI Prolog to query for the attachable predicate as defined in rulesFactsManual.pl
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

# sys.args[1]: File containing annotated attack trees, one per line
# sys.args[2]: File containing list of CVEs
# sys.args[3]: Output file

cves = ' '.join(ln.strip() for ln in open(sys.argv[2], 'rt').readlines()).split()

lns = open(sys.argv[1], 'rt').readlines()
outf = open(sys.argv[3], 'wt')

for ln in lns:
    atree = AnnotatedAttackTreeParser().get_tree(ln.strip())
    if atree is not None:
        for cve in cves:
            refine(atree, cve)
        consolidate_enriched_tree(atree)
        outf.write(aatree_as_str(atree))

outf.close()
    

