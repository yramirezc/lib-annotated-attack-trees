# Convert plain text files containing the automatically extracted assumptions and guarantees into Prolog files

# sys.argv[1]: Plain text assumptions file
# sys.argv[2]: Prolog KB assumptions file
# sys.argv[3]: Plain text guarantees file 
# sys.argv[4]: Prolog KB guarantees file

import sys

def adaptAssumptions2PrologSyntax(txt_args):
    replacements = {'-': '_', '.': '_dot_', '=': '_eq_', '\'': '_apostr_', '@': '_at_', '#': '_sharp_', '/': '_slash_', '\\': '_bckslash_', '*': 'any_', '(': '_lpar_', ')': '_rpar_', '!': '_exclam_', '+': '_plus_', '&': '_amp_', '"': '_quote_', '%': '_pct_', '?': '_quest_mark_', '$': '_dollar_sgn_'}
    correct_args = txt_args.lower().replace('::', ':').replace(':', ',')    # Colon-separated ids to Prolog lists 
    for repl in replacements:
        correct_args = correct_args.replace(repl, replacements[repl]) 
    correct_args = correct_args.replace(',_', ',z_').replace('[_', '[z_')   # Remove false variables introduced by previous replacements
    if correct_args[0] == '_':
        correct_args = 'z' + correct_args
    for char in '0123456789':
        correct_args = correct_args.replace(',' + char, ',n_' + char)
        correct_args = correct_args.replace('[' + char, '[n_' + char)
        if correct_args[0] == char:
            correct_args = 'n_' + correct_args
    return correct_args

def adaptGuarantees2PrologSyntax(txt_args):
    replacements = {'-': '_', '.': '_dot_', ':': '_colon_', '=': '_eq_', '\'': '_apostr_', '@': '_at_', '#': '_sharp_', '/': '_slash_', '\\': '_bckslash_'}
    correct_args = txt_args.lower().replace('{', '[').replace('}', ']')    # Plain text sets to Prolog lists 
    for repl in replacements:
        correct_args = correct_args.replace(repl, replacements[repl]) 
    correct_args = correct_args.replace(',_', ',z_').replace('[_', '[z_')   # Remove false variables introduced by previous replacements
    for char in '0123456789':
        correct_args = correct_args.replace(',' + char, ',n_' + char)
        correct_args = correct_args.replace('[' + char, '[n_' + char)
    return correct_args

if len(sys.argv) == 5:
    
    # Translate assumptions file
        
    out_assumptions = open(sys.argv[2], 'wt')
    out_assumptions.write('/**\n * Automatically generated assumption-related facts\n */\n\n')
    lns = open(sys.argv[1], 'rt').readlines()
    
    for ln in lns:
        fields = ln.strip().split('|')
        cveId = fields[0].replace('-', '_').lower()
        for snp in fields[1 : len(fields)]:
            if snp != '':   # No fact definitions
                for spec in snp.split():
                    spec = spec.strip()   # Just in case
                    name = spec[0 : spec.find('(')]
                    orig_args = spec[spec.find('(') + 1 : len(spec) - 1]
                    out_assumptions.write(name + '(' + cveId + ',[' + adaptAssumptions2PrologSyntax(orig_args) + ']).\n')
                    
    out_assumptions.close()
    
    # Translate guarantees file
        
    out_guarantees = open(sys.argv[4], 'wt')
    out_guarantees.write('/**\n * Automatically generated guarantee-related facts\n */\n\n')
    lns = open(sys.argv[3], 'rt').readlines()
    
    for ln in lns:
        fields = ln.strip().split('|')
        cveId = fields[0].replace('-', '_').lower()
        for snp in fields[1 : len(fields)]:
            if snp != '':   # No fact definitions
                for spec in snp.split():
                    spec = spec.strip()   # Just in case
                    name = spec[0 : spec.find('(')]
                    orig_args = spec[spec.find('(') + 1 : len(spec) - 1]
                    out_guarantees.write(name + '(' + cveId + ',[' + adaptGuarantees2PrologSyntax(orig_args) + ']).\n')
                    
    out_guarantees.close()
    
    
