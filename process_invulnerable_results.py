#!/usr/bin/python3
import sys
import json

file = sys.argv[1]

map_of_rels = {
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

list_of_analytics = [
  'disassemble_time',
  'decomp_time',
  'inline_time',
  'client_time',
]

def process_result_file(filename, output_set=None):
    filemap = dict()

    for rel in set(map_of_rels.values()):
        filemap[rel] = set()

    for analytic in list_of_analytics:
        filemap[analytic] = 0

    filemap['contract_set'] = set()
    filemap['has_output'] = set()

    rels = set(map_of_rels.keys())
    with open(filename) as json_file:
        data = json.load(json_file)
        for contract in data:
            name = contract[0].replace('.hex', '')
            have_output = set(contract[1])

            filemap['contract_set'].add(name)

            filemap[name] = dict()
            filemap[name]["rels"] = have_output
            filemap[name]["analytics"] = contract[3]
            if output_set and name not in output_set:
                continue
            if have_output:
                filemap['has_output'].add(name)

            for rel in rels & have_output:
                filemap[map_of_rels[rel]].add(name)

            for analytic in list_of_analytics:
                if analytic in contract[3]:
                    filemap[analytic] += contract[3][analytic]

            #break
    return filemap


res_map = process_result_file(file)

number_with_output = len(res_map['has_output'])
all_contracts = len(res_map['contract_set'])

print(f'Successfully analyzed {number_with_output} out of {all_contracts} contracts ({round(100 * number_with_output/float(all_contracts))}%).')

ir_gen_time = round(res_map['disassemble_time'] + res_map['decomp_time'] + res_map['inline_time'])
symvalic_time = round(res_map['client_time'])

print(f'Total analysis time (excluding timeouts): {ir_gen_time + symvalic_time} seconds')
print(f'Average analysis time (excluding timeouts): {round((ir_gen_time + symvalic_time)/float(all_contracts), 2)} seconds')

print('\nContracts flagged for each vulnerability type:')
for rel in set(map_of_rels.values()):
    not_in_file1 = res_map[rel]
    print('\033[1m{0:45} \033[0m{1}'.format(rel, len(res_map[rel])))

