import difflib
import re


def extract_methods(java_code):
    # Pattern migliorato per catturare firme di metodi multilinea
    method_pattern = re.compile(
        r'^\s*(public|private|protected|static|final|synchronized|abstract|native|default)?'  # Modificatore singolo
        r'(\s*(public|private|protected|static|final|synchronized|abstract|native|default))*'  # Modificatori multipli
        r'\s*(<\w+>)?'  # Tipo generico opzionale
        r'\s*[\w<>\[\]]+\s+[\w<>\[\]]+\s*\([^)]*\)',  # Tipo di ritorno e nome del metodo con parametri
        #r'\s*(throws\s+[\w<>]+(\s*,\s*[\w<>]+)*)?'  # Clausola throws opzionale
        #r'\s*\{',
        re.MULTILINE)  # Apertura di graffa

    methods = method_pattern.finditer(java_code)
    method_dict = {}

    for method in methods:
        start = method.start()
        method_signature = method.group()
        # Contatore delle parentesi graffe
        brace_counter = 1

        # Scansiona il codice a partire dalla fine della firma del metodo
        for i in range(start + len(method_signature), len(java_code)):
            if java_code[i] == '{':
                brace_counter += 1
            elif java_code[i] == '}':
                brace_counter -= 1

            # Se abbiamo trovato tutte le parentesi graffe corrispondenti
            if brace_counter == 0:
                # Estrai il corpo del metodo compresa la firma
                method_body = java_code[start:i + 1]
                method_dict[method_signature.strip()] = method_body.strip()
                break

    return method_dict


def add_mutate_comment(vuln_body, fixed_body):
    # Crea un differenziatore tra le due stringhe, linea per linea
    diff = difflib.ndiff(vuln_body.splitlines(), fixed_body.splitlines())

    # Lista per tenere traccia del codice fixed con commenti MUTATE
    fixed_with_mutate = []

    for line in diff:
        if line.startswith(' '):  # Linea uguale
            fixed_with_mutate.append(line[2:])
        elif line.startswith('-'):  # Linea solo nel metodo vulnerabile
            continue  # Ignora linea solo vulnerabile
        elif line.startswith('+'):  # Linea modificata nel metodo fisso
            fixed_with_mutate.append(line[2:] + '  // <MUTATE>')  # Aggiungi il commento MUTATE

    return '\n'.join(fixed_with_mutate)


def find_differing_methods(vuln_methods, fixed_methods):
    fixed_methods_list = []
    vuln_methods_list = []

    for key1, key2 in zip(vuln_methods.keys(), fixed_methods.keys()):
        print(f"{key1}, {key2}")

    for method_signature, vuln_body in vuln_methods.items():
        fixed_body = fixed_methods.get(method_signature, None)

        if fixed_body is None:
            continue  # Metodo non trovato nella classe fixed

        # Confronto tra i corpi dei metodi
        if vuln_body != fixed_body:
            fixed_with_mutate = add_mutate_comment(vuln_body, fixed_body)
            fixed_methods_list.append(fixed_with_mutate)
            vuln_methods_list.append(vuln_body)

    return fixed_methods_list, vuln_methods_list


def compare_classes(vuln_file, fixed_file):
    with open(vuln_file, 'r') as f1, open(fixed_file, 'r') as f2:
        vuln_code = f1.read()
        fixed_code = f2.read()

    # Estrai i metodi da entrambe le classi
    vuln_methods = extract_methods(vuln_code)
    fixed_methods = extract_methods(fixed_code)

    # Trova i metodi che differiscono
    fixed_methods_list, vuln_methods_list = find_differing_methods(vuln_methods, fixed_methods)

    return fixed_methods_list, vuln_methods_list


def extract_method_name_from_signature(signature):
    # L'espressione regolare cerca il nome del metodo
    match = re.search(r'\b\w+\s+(\w+)\s*\(', signature)
    if match:
        # Estrae la parte del nome del metodo
        name = match.group(1)
        return name
    return None


def extract_method_signature(method_code):
    # Pattern per catturare la firma del metodo
    pattern = r'\b(.*?)\s+(\w+)\s*\([^)]*\)'

    match = re.search(pattern, method_code)
    if match:
        # Restituiamo tutta la firma trovata, gruppo 0 contiene l'intero match
        return match.group(0)
    else:
        return None


def extract_options(text):
    pattern = r'Option \d:\s*```java\s*(.*?)\s*```'
    matches = re.findall(pattern, text, re.DOTALL)
    return [match.strip() for match in matches]


def replace_method(class_content: str, new_method: str, method_signature: str) -> str:
    escaped_signature = re.escape(method_signature)
    method_start = re.search(escaped_signature, class_content)

    if not method_start:
        return class_content  # Se il metodo non viene trovato, restituisce il contenuto originale

    start_index = method_start.start()

    opening_brace_index = class_content.find("{", method_start.end())

    if opening_brace_index == -1:
        return class_content  # Se non trova la parentesi graffa, restituisce il contenuto originale

    brace_count = 1
    end_index = opening_brace_index + 1

    while brace_count > 0 and end_index < len(class_content):
        if class_content[end_index] == '{':
            brace_count += 1
        elif class_content[end_index] == '}':
            brace_count -= 1
        end_index += 1

    new_class_content = class_content[:start_index] + new_method.strip() + class_content[end_index:]

    return new_class_content
