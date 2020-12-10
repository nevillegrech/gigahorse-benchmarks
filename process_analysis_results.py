#!/usr/bin/env python
'''Usage: ./process_analysis_results.py <name of tool> <filepath of results>'''
import sys
import os
import json
from pandas import DataFrame
from collections import defaultdict
from os.path import abspath, dirname, join, getsize

BENCHMARKS_DIR = dirname(abspath(__file__))

class Evaluator:
    def __init__(self, filepath):
        # read labels
        with open(join(BENCHMARKS_DIR, 'labels.json')) as f:
            self.labels = json.load(f)
        # read the rest of the results
        self.init(filepath)

    def init(self,filepath):
        raise NotImplementedError("TODO")
    
class GigahorseEvaluator(Evaluator):

    def init(self, filepath):
        with open(filepath) as f:
            results_json = json.load(f)
        self.gigahorse_flags = {name: {k for k, v in vulns.items() if isinstance(v, str) and v} for name, _, _, vulns in results_json}
            
            
    def process_results(self):
        results = []
        results_per_vuln = set()

        for label in self.labels:
            example = label['bytecode-path']
            example_len = len(open(join(join(BENCHMARKS_DIR, 'vulnerable-bytecode'), example)).read())
            expected_vulnerability_type = None
            for v in self.mappings.values():
                if example.startswith(v):
                    expected_vulnerability_type = v
                    continue
            true_positives = False
            false_positives = 0
            for k, v in self.mappings.items():
                is_vuln = example in self.gigahorse_flags and k in self.gigahorse_flags[example]
                if v == expected_vulnerability_type:
                    true_positives |=  is_vuln
                    if is_vuln:
                        results_per_vuln.add((example, k, 0, 1, example_len))
                else:
                    false_positives += int(is_vuln)
                    if is_vuln:
                        results_per_vuln.add((example, k, 1, 0, example_len))
    
            results.append((example, expected_vulnerability_type, int(true_positives), false_positives, example_len))
        return results, results_per_vuln


class EthaneEvaluator(GigahorseEvaluator):
    mappings = {
        'Vulnerability_AccessibleSelfdestruct': 'access_control',
        'Vulnerability_TaintedDelegatecall': 'access_control',
        'Vulnerability_TaintedSelfdestruct': 'access_control',
        'Vulnerability_TaintedValueSend': 'access_control',
        'LoadedDice': 'bad_randomness',
        'Reentrancy': 'reentrancy',
        'UnboundedMassOp': 'denial_of_service',
        'WalletGriefing': 'denial_of_service',
    }

class SymvalicEvaluator(GigahorseEvaluator):
    mappings = {
        'Symbolic_AccessibleSelfDestruct': 'access_control',
        'Symbolic_TaintedSelfDestruct': 'access_control',
        'Symbolic_TaintedDelegateCall': 'access_control',
        'Symbolic_ArithmeticError': 'arithmetic',
        'Symbolic_BadRandomness': 'bad_randomness',
        'Symbolic_Reentrancy': 'reentrancy',
        'Symbolic_TaintedOwnershipGuard': 'access_control',
        'Symbolic_UnboundedIteration': 'denial_of_service',
        'Symbolic_UncheckedLowLevelCall': 'unchecked_low_level_call',
        'Symbolic_WalletGriefingLoose': 'denial_of_service',
        'Symbolic_TimeManipulation': 'time_manipulation'
    }

evaluator = eval(sys.argv[1]+'Evaluator')(sys.argv[2])

results, results_per_vuln = evaluator.process_results()

# construct dataframe
results_df = DataFrame({
    'expected_vulnerability_type' : {i: v for i, v, tp, fp, _ in results},
    'tp' : {i: tp for i, v, tp, fp, _ in results},
    'fp' : {i: fp for i, v, tp, fp, _ in results},
    'fn' : {i: int(tp == 0) for i, v, tp, fp, _ in results},
    'total_v' : {i: 1 for i, v, tp, fp, _ in results},
    'example_len' : {i: e for i, v, tp, fp, e in results}
})

results_per_vuln_df = DataFrame({
    'example': {i: e for i, (e,v,fp,tp,_) in enumerate(results_per_vuln)},
    'vulnerability': {i: v for i, (e,v,fp,tp,_) in enumerate(results_per_vuln)},
    'tp': {i: tp for i, (e,v,fp,tp,_) in enumerate(results_per_vuln)},
    'fp': {i: fp for i, (e,v,fp,tp,_) in enumerate(results_per_vuln)},
    'example_len': {i: example_len for i, (e,v,_,_,example_len) in enumerate(results_per_vuln)},
})

results_per_vuln_grouped = results_per_vuln_df.groupby('vulnerability').sum()
results_per_vuln_grouped['tp/fp'] = results_per_vuln_grouped.tp / results_per_vuln_grouped.fp

results_grouped = results_df.groupby('expected_vulnerability_type').sum()

def compute_pr(df):
    df['precision'] = df.tp / (df.tp + df.fp)
    df['recall'] = df.tp / (df.tp + df.fn)
    df['F1'] = df.precision * df.recall / (df.precision + df.recall)

compute_pr(results_grouped)

print(results_grouped)
print()
print(results_per_vuln_grouped.sort_values('tp/fp'))

import pdb; pdb.set_trace()
