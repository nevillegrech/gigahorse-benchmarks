import os
import json

DEFAULT_LABEL_PATH = os.path.join(os.path.dirname(__file__), 'labels.json')

def read_labels(label_path=DEFAULT_LABEL_PATH):
    labels = []

    with open(label_path) as f:
        return json.load(f)

def write_labels(labels, label_path=DEFAULT_LABEL_PATH):
    with open(label_path, 'w') as f:
        def print_indent(string, level=0):
            print('    ' * level + string, file=f)

        print_indent('[')
        
        for cur_lab, label in enumerate(labels):
            print_indent('{', 1)
        
            for field in ['id', 'source-path', 'contract-name', 'bytecode-path', 'origin']:
                print_indent(f'"{field}": "{label[field]}",', 2)
        
            if not label['vulnerabilities']:
                print_indent('"vulnerabilities": []', 2)
            else:
                print_indent('"vulnerabilities": [', 2)
        
                for i, vuln in enumerate(label['vulnerabilities']):
                    print_indent('{', 3)
        
                    if 'lines' in vuln:
                        print_indent(f'"lines": [{", ".join(str(x) for x in vuln["lines"])}],', 4)
                    
                    print_indent(f'"category": "{vuln["category"]}"', 4)
        
        
                    if i == len(label['vulnerabilities']) - 1:
                        print_indent('}', 3)
                    else:
                        print_indent('},', 3)
        
                print_indent(']', 2)
            
            if cur_lab == len(labels) - 1:
                print_indent('}', 1)
            else:
                print_indent('},', 1)
        
        print_indent(']')
