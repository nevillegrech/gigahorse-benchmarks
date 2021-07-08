#!/usr/bin/python3
'''Usage: ./process_analysis_results.py <name of tool> <filepath of results>'''
import sys
import json
from collections import defaultdict
from os.path import abspath, dirname, join, getsize

BENCHMARKS_DIR = dirname(abspath(__file__))
INTERACTIVE = True
assert __name__ == '__main__', "Not a library"

class Evaluator:
    def __init__(self, filepath):
        # read labels
        with open(join(BENCHMARKS_DIR, 'labels.json')) as f:
            self.labels = json.load(f)
            self.label_dict = {label['bytecode-path']: label for label in self.labels}
        # read the rest of the results
        self.init(filepath)

    def init(self,filepath):
        raise NotImplementedError("TODO")
    
class GigahorseEvaluator(Evaluator):

    def init(self, filepath):
        with open(filepath) as f:
            results_json = json.load(f)
        self.gigahorse_flags = {name: vulns for name, vulns, _, _ in results_json}
        self.gigahorse_analytics = {name: analytics for name, _, _, analytics in results_json}
            
            
    def process_results(self):
        
        true_positives = dict()
        false_positives = dict()
        all_vulns = dict()

        symvalic_time = 0.0
        for analytics in self.gigahorse_analytics.values():
            symvalic_time += analytics['disassemble_time'] + analytics['decomp_time'] + analytics['inline_time'] + analytics['client_time']

        for v in self.supported_vulnerabilities:
            true_positives[v] = set()
            false_positives[v] = set()
            all_vulns[v] = set()

        for label in self.labels:
            example = label['bytecode-path'].split('/')[-1]
            vuln_category = label['vulnerabilities'][0]["category"]
            if vuln_category in all_vulns:
                all_vulns[vuln_category].add(example)
            
        for label in self.labels:
            example = label['bytecode-path'].split('/')[-1]
            
            try:
                expected_vulnerability_type = label['vulnerabilities'][0]["category"]
            except (KeyError, IndexError):
                expected_vulnerability_type = None
            for v in self.mappings.values():
                if example.startswith(v):
                    expected_vulnerability_type = v
                    continue

            for k, v in self.mappings.items():
                is_vuln = example in self.gigahorse_flags and k in self.gigahorse_flags[example]
                if is_vuln:
                    if v == expected_vulnerability_type:
                        true_positives[v].add(example)
                    else:
                        false_positives[v].add(example)
        
        number_with_output = len(self.gigahorse_flags)
        all_contracts = len(self.labels)
        print(f'Successfully analyzed {number_with_output} out of {all_contracts} contracts ({round(100 * number_with_output/float(all_contracts))}%).')

        print(f'Total analysis time (excluding timeouts): {round(symvalic_time)} seconds')
        print(f'Average analysis time (excluding timeouts): {round((symvalic_time)/float(109), 2)} seconds')

        print('\n{0:30}\t{1}\t{2}\t{3}\t{4}\t{5}'.format('Vulnerability', 'TP', 'FP', 'FN', 'Precision', 'Recall'))
        for v in self.supported_vulnerabilities:
            tps = len(true_positives[v])
            fps = len(false_positives[v])
            fns = len(all_vulns[v] - true_positives[v])
            precision = round(100 * tps/float(tps+fps))
            recall = round(100 * tps/float(len(all_vulns[v])))
            print('{0:30}\t{1}\t{2}\t{3}\t{4}\t\t{5}'.format(v, tps, fps, fns, precision, recall))
            #print(f"\033[1m{v}: \033[0mTPs: {tps}, FPs: {fps}, FNs: {fns}, Precision: {precision}%, Recall {recall}%")




class SymvalicEvaluator(GigahorseEvaluator):
    mappings = {
        'Symbolic_AccessibleSelfDestruct': 'access_control',
        'Symbolic_TaintedSelfDestruct': 'access_control',
        'Symbolic_TaintedDelegateCall': 'access_control',
        'Symbolic_ArithmeticErrorHighConfidence': 'arithmetic',
        'Symbolic_Reentrancy': 'reentrancy',
        'Symbolic_TaintedOwnershipGuard': 'access_control',
        'Symbolic_UnboundedIteration': 'denial_of_service',
        'Symbolic_UncheckedLowLevelCall': 'unchecked_low_level_calls',
        'Symbolic_WalletGriefingLoose': 'denial_of_service'
    }
    supported_vulnerabilities = set(val for val in mappings.values())

evaluator = SymvalicEvaluator(sys.argv[1])

evaluator.process_results()
