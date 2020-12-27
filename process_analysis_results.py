#!/usr/bin/env python
'''Usage: ./process_analysis_results.py <name of tool> <filepath of results>'''
import sys
import os
import json
from pandas import DataFrame
from collections import defaultdict
from os.path import abspath, dirname, join, getsize

BENCHMARKS_DIR = dirname(abspath(__file__))
INTERACTIVE = True
assert(__name__ == '__main__', "Not a library")

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
        self.gigahorse_flags = {name: vulns for name, vulns, _, _ in results_json}
            
            
    def process_results(self):
        results = []
        results_per_vuln = set()

        for label in self.labels:
            example = label['bytecode-path'].split('/')[-1]
            try:
                program_size = len(open(join(BENCHMARKS_DIR, label['bytecode-path'])).read())
            except IOError:
                # not found
                program_size = 0
            # find vulnerability type
            try:
                expected_vulnerability_type = label['vulnerabilities'][0]["category"]
            except (KeyError, IndexError):
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
                        results_per_vuln.add((example, k, 0, 1, program_size))
                else:
                    false_positives += int(is_vuln)
                    if is_vuln:
                        results_per_vuln.add((example, k, 1, 0, program_size))
    
            results.append((example, expected_vulnerability_type, int(true_positives), false_positives, program_size))
        return results, results_per_vuln


class EthaneEvaluator(GigahorseEvaluator):
    mappings = {
        'ArithmeticOverflow': 'arithmetic',
        'AccessibleSelfdestruct': 'access_control',
        'TaintedDelegatecall': 'access_control',
        'TaintedSelfdestruct': 'access_control',
        'TaintedValueSend': 'access_control',
        'LoadedDice': 'bad_randomness',
        'Reentrancy': 'reentrancy',
        'UnboundedMassOp': 'denial_of_service',
        'WalletGriefing': 'denial_of_service',
        'UncheckedLowLevelCall': 'unchecked_low_level_call'
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

flagged_by_oracle, flagged_by_tool = evaluator.process_results()

# construct dataframe
flagged_by_oracle = DataFrame({
    'expected_vulnerability_type' : {i: v for i, v, tp, fp, _ in flagged_by_oracle},
    'tp' : {i: tp for i, v, tp, fp, _ in flagged_by_oracle},
    'fp' : {i: fp for i, v, tp, fp, _ in flagged_by_oracle},
    'fn' : {i: int(tp == 0) for i, v, tp, fp, _ in flagged_by_oracle},
    'total_v' : {i: 1 for i, v, tp, fp, _ in flagged_by_oracle},
    'program_size' : {i: e for i, v, tp, fp, e in flagged_by_oracle}
})

flagged_by_tool = DataFrame({
    'example': {i: e for i, (e,v,fp,tp,_) in enumerate(flagged_by_tool)},
    'vulnerability': {i: v for i, (e,v,fp,tp,_) in enumerate(flagged_by_tool)},
    'tp': {i: tp for i, (e,v,fp,tp,_) in enumerate(flagged_by_tool)},
    'fp': {i: fp for i, (e,v,fp,tp,_) in enumerate(flagged_by_tool)},
    'program_size': {i: program_size for i, (e,v,_,_,program_size) in enumerate(flagged_by_tool)},
})

flagged_by_tool_grouped = flagged_by_tool.groupby('vulnerability').sum()
flagged_by_tool_grouped['tp/fp'] = flagged_by_tool_grouped.tp / flagged_by_tool_grouped.fp

flagged_by_oracle_grouped = flagged_by_oracle.groupby('expected_vulnerability_type').sum()

def compute_pr(df):
    df['precision'] = df.tp / (df.tp + df.fp)
    df['recall'] = df.tp / (df.tp + df.fn)
    df['F1'] = df.precision * df.recall / (df.precision + df.recall)

compute_pr(flagged_by_oracle_grouped)

print(flagged_by_oracle_grouped)
print()
print(flagged_by_tool_grouped.sort_values('tp/fp'))

if INTERACTIVE:
    descriptions = {
        'flagged_by_oracle': "Useful for examining false negatives for a particular tool, and plotting results in a paper.",
        'flagged_by_tool': "Useful for finding which analyses produce the most false positives for a particular tool",
        'flagged_by_oracle_grouped': "As above, but grouped by vulnerability",
        'flagged_by_tool_grouped': "As above, but grouped by vulnerability",
       }
    print('Entering interactive mode, you can query the following Pandas dataframes using the PDB shell')
    print('-'*80)
    for k, v in descriptions.items():
        assert k in globals()
        print(f'{k}: {v}')
    
    import pdb; pdb.set_trace()
