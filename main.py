import math
from openai import OpenAI
from utils.classes_funcions import compare_classes, replace_method, extract_method_signature, extract_options, \
    extract_method_name_from_signature, replace_mutant_method
from utils.run_docker_container import run_docker_container
import json
import os
import google.generativeai as genai
import pandas as pd
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib import rcParams
from matplotlib_venn import venn2, venn2_circles, venn3, venn3_circles

GEMINI_API_KEY = os.environ.get('GOOGLE_API_KEY')
CHATGPT_API_KEY = os.environ.get('OPENAI_API_KEY')

keyword_strong_substitution = "\"SS\""
keyword_strong_substitution_with_add_tests_failed = "\"SS+ATF\""
keyword_test_substitution = "\"TS\""
keyword_test_substitution_with_add_tests_failed = "\"TS+ATF\""
keyword_partial_substitution = "\"PS\""
keyword_partial_substitution_with_add_tests_failed = "\"PS+ATF\""
keyword_partial_test_substitution = "\"PTS\""
keyword_partial_test_substitution_with_add_tests_failed = "\"PTS+ATF\""
keyword_no_substitution = "\"NS\""
keyword_mutant_not_killed = "\"MNK\""
keyword_compilation_error = "\"CE\""



def checkout_vulnerability(path_dir, vul_id, container):
    if os.path.exists(path_dir + "/" + vul_id):
        print(f"Checkout {vul_id} already done\n")
        return False
    else:
        command_to_execute = ["vul4j", "checkout", "--id", vul_id, "-d", "/data/code_dir" + "/" + vul_id]
        print("executing", command_to_execute)
        exit_code, output = container.exec_run(command_to_execute)
        print(output.decode("utf-8"))
        return True


def checkout(container):
    file_path = 'projects_to_test.txt'

    with open(file_path, 'r') as file:
        for line in file:
            vul_id, cve = line.strip().split(" - ")
            checkout_vulnerability("vul4j/code_dir", vul_id, container)


def generate_mutants(fixed_code, vulnerable_code, file_name, class_path, vul_id, container):

    with open(class_path, "r") as class_file_content:
        class_content_code = class_file_content.read()

    prompt1 = (f"Create a mutant for the following method by applying one of the mutation operators used for mutation "
              f"testing only in the code line marked with //MUTATE. "
              f"The task is to improve code testing by checking whether changes made to fixed code introduce or "
              f"detect vulnerabilities. it is very important that you do not produce mutants "
              f"equal to fixed code or identical to each other .\n Fixed code: {fixed_code}\n"
              f"Vulnerable code: {vulnerable_code}\n Please consider changes such as using different operators, "
              f"changing constants, referring to different variables, object properties, functions, methods or any "
              f"other mutation operator you consider useful for the purpose. "
              f"Provide ten answers as fenced code blocks containing only"
              f" the mutated lines, using the following template: "
              f"Option 1: The lines can be replaced with: ```java <code fragment> ``` "
              f"Option 2: The lines can be replaced with: ```java <code fragment> ``` "
              f"Option 3: The lines can be replaced with: ```java <code fragment> ``` "
              f"..."
              f"Option 10: The lines can be replaced with: ```java <code fragment> ``` ")

    prompt2 = (f"Create a mutant for the following method by applying one of the mutation operators used for mutation "
               f"testing only in the code line marked with //MUTATE. "
               f"The task is to improve code testing by checking whether changes made to fixed code introduce or "
               f"detect vulnerabilities. it is very important that you do not produce mutants "
               f"equal to fixed code or identical to each other .\n Fixed code: {fixed_code}\n"
               f"Vulnerable code: {vulnerable_code}\n Please consider changes such as using different operators, "
               f"changing constants, referring to different variables, object properties, functions, methods or any "
               f"other mutation operator you consider useful for the purpose . "
               f"Provide ten answers as fenced code blocks containing only"
               f" the mutated lines, using the following template: "
               f"Option 1: The lines can be replaced with: ```java <code fragment> ``` "
               f"Option 2: The lines can be replaced with: ```java <code fragment> ``` "
               f"Option 3: The lines can be replaced with: ```java <code fragment> ``` "
               f"..."
               f"Option 10: The lines can be replaced with: ```java <code fragment> ``` "
               f"Please take your time with the implementation, as this is very important to my career")

    prompt3 = (f"Create a mutant for the following method by applying one of the mutation operators used for mutation "
               f"testing only in the code line marked with //MUTATE. "
               f"The task is to improve code testing by checking whether changes made to fixed code introduce or "
               f"detect vulnerabilities. it is very important that you do not produce mutants "
               f"equal to fixed code or identical to each other .\n Class code: {class_content_code}\n"
               f" Fixed code: {fixed_code}\n"
               f"Vulnerable code: {vulnerable_code}\n Please consider changes such as using different operators, "
               f"changing constants, referring to different variables, object properties, functions, methods or any "
               f"other mutation operator you consider useful for the purpose . "
               f"Provide ten answers as fenced code blocks containing only"
               f" the mutated lines, using the following template: "
               f"Option 1: The lines can be replaced with: ```java <code fragment> ``` "
               f"Option 2: The lines can be replaced with: ```java <code fragment> ``` "
               f"Option 3: The lines can be replaced with: ```java <code fragment> ``` "
               f"..."
               f"Option 10: The lines can be replaced with: ```java <code fragment> ``` "
               f"Please take your time with the implementation, as this is very important to my career")

    with open(os.path.dirname(class_path) + "\\paths.json", 'r') as file:
        data = json.load(file)
    source_class_path = "vul4j/code_dir/" + vul_id + "/" + data.get(os.path.basename(class_path))
    print("Class to mutate: ", source_class_path)
    mutated_path = Path("vul4j/code_dir/" + vul_id + "/VUL4J/mutated_code")
    prompt = "prompt1"
    model = "gemini"
    mutated_path = mutated_path.joinpath(model)
    if not mutated_path.exists():
        mutated_path.mkdir()
    mutated_path = mutated_path.joinpath(prompt)
    if not mutated_path.exists():
        mutated_path.mkdir()
    mutated_path = mutated_path.joinpath(file_name)
    if not mutated_path.exists():
        mutated_path.mkdir(parents=True, exist_ok=True)

    if model == "chatgpt":
        if mutated_path.joinpath('chatgpt_response.txt').exists():
            return

        print("Mutant generation by ChatGPT...")
        client = OpenAI(api_key=CHATGPT_API_KEY)
        completion = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "user",
                    "content": prompt2
                }
            ]
        )

        with open(mutated_path.joinpath('chatgpt_response.txt'), 'w') as file:
            response = completion.choices[0].message.content
            file.write(response)
    else:
        if mutated_path.joinpath('gemini_response.txt').exists():
            return

        genai.configure(api_key=GEMINI_API_KEY)
        gemini_model = genai.GenerativeModel("gemini-pro")
        print("Mutant generation by Gemini...")
        response_result = gemini_model.generate_content(prompt2)

        with open(mutated_path.joinpath('gemini_response.txt'), 'w') as file:
            file.write(response_result.text)
        response = response_result.text

    options = extract_options(response)
    if len(options) == 0 or len(options) != 10:
        print("The answer does not respect the required format, to be repeated")
        generate_mutants(fixed_code, vulnerable_code, mutated_path, class_path, vul_id, container)

    # Creazione delle dieci versioni della classe Java per ogni metodo mutato
    for i, option in enumerate(options, 1):
        signature = extract_method_signature(fixed_code)
        method_name = extract_method_name_from_signature(signature)
        print(f"MUTANT OF METHOD {method_name} NO.{i}")

        with open(class_path, 'r', encoding='utf-8') as class_content:
            class_content_with_mutate_comment = replace_method(class_content.read(), fixed_code, signature)
            with open("method.txt", 'w', encoding='utf-8') as file:
                file.write(class_content_with_mutate_comment)
            modified_class_content = replace_mutant_method(class_content_with_mutate_comment, option, signature)
        mutant_path = mutated_path.joinpath(f'mutant_option_{method_name}_{i}')
        if not mutant_path.exists():
            mutant_path.mkdir()
        mutant_path = mutant_path.joinpath(f'mutant_option_{i}.java')
        with open(mutant_path, 'w') as file:
            file.write(modified_class_content)

        execute_compile(mutant_path, source_class_path, vul_id, container)

def get_compilation_results(path_dir):
    bool_compiled = None
    path_compile_result_text_file = path_dir.joinpath("compile_result.txt")
    if os.path.exists(path_compile_result_text_file):
        compile_result_text_file = open(path_compile_result_text_file, "r")
        content_compile_result_text_file = compile_result_text_file.read()
        compile_result_text_file.close()
        if content_compile_result_text_file == "1":
            bool_compiled = True
        else:
            bool_compiled = False
    return bool_compiled


def execute_compile(mutant_path, source_class_path, vul_id, container):
    destination_path = mutant_path.parent
    if os.path.exists(str(destination_path) + "/compile.log") and os.path.exists(str(destination_path) + "/compile_result.txt"):
        return

    file_mutant = open(mutant_path, "r")
    content_mutant = file_mutant.read()
    file_mutant.close()

    file_fixed = open(source_class_path, "r")
    content_fixed = file_fixed.read()
    file_fixed.close()

    file_to_change = open(source_class_path, "w")
    file_to_change.write(content_mutant)
    file_to_change.close()

    command_to_execute = ["vul4j", "compile", "-d", "/data/code_dir/" + vul_id]
    print("executing", command_to_execute)
    exit_code, output = container.exec_run(command_to_execute)
    print(output.decode("utf-8"))

    destination_path = str(destination_path).replace("vul4j", "data")
    copy_command = ["cp", "/data/code_dir/" + vul_id + "/VUL4J/compile.log", destination_path.replace("\\", "/")]
    print("executing", copy_command)
    exit_code, output = container.exec_run(copy_command)
    print(output.decode("utf-8"))

    copy_command = ["cp", "/data/code_dir/" + vul_id + "/VUL4J/compile_result.txt", destination_path.replace("\\", "/")]
    print("executing", copy_command)
    exit_code, output = container.exec_run(copy_command)
    print(output.decode("utf-8"))

    execute_tests_and_get_results(mutant_path, vul_id, container)

    file_to_change = open(source_class_path, "w")
    file_to_change.write(content_fixed)
    file_to_change.close()


def get_test_results(path_dir):
    test_passed = None
    path_testing_results_json_file = path_dir.joinpath("testing_results.json")
    if os.path.exists(path_testing_results_json_file):
        file_testing_results_json = open(path_testing_results_json_file)
        try:
            content_testing_results_json_file = json.load(file_testing_results_json)
        except:
            print("error in loading json")
            content_testing_results_json_file = ""
        file_testing_results_json.close()
        if content_testing_results_json_file != "":
            overall_metrics = content_testing_results_json_file["tests"]["overall_metrics"]
            number_error = overall_metrics["number_error"]
            number_failing = overall_metrics["number_failing"]
            if number_error == 0 and number_failing == 0:
                print("All tests passed, 0 error and 0 failures")
                test_passed = True
            else:
                print("Error: ", number_error, " Failures: ", number_failing)
                test_passed = False
    return test_passed


def execute_tests_and_get_results(mutant_path, vul_id, container):
    destination_path = mutant_path.parent
    if os.path.exists(str(destination_path) + "/testing.log") and os.path.exists(str(destination_path) +
                                                                                 "/testing_results.json"):
        return

    path_dir = "vul4j/code_dir"
    bool_compiled = get_compilation_results(mutant_path.parent)
    bool_test_passed = None
    if bool_compiled is None:
        print("compiled", vul_id, ", but coudn't find the compilation results!")
    elif bool_compiled is True:
        command_to_execute = ["vul4j", "test", "-d", "/data/code_dir/" + vul_id]
        print("executing", command_to_execute)

        try:
            container.exec_run(command_to_execute)
        except Exception:
            print("An error has occurred in mutant testing")
        bool_test_passed = get_test_results(Path(path_dir + "/" + vul_id + "/VUL4J"))
        if bool_test_passed is None:
            print("tests executed for", vul_id, ", but coudn't find the test results!")
        elif bool_test_passed is True:
            print("all tests passed for", vul_id)
        else:
            print("tests failed for", vul_id)

        destination_path = str(destination_path).replace("vul4j", "data")
        copy_command = ["cp", "/data/code_dir/" + vul_id + "/VUL4J/testing.log", destination_path.replace("\\", "/")]
        print("executing", copy_command)
        exit_code, output = container.exec_run(copy_command)
        print(output.decode("utf-8"))

        copy_command = ["cp", "/data/code_dir/" + vul_id + "/VUL4J/testing_results.json",
                        destination_path.replace("\\", "/")]
        print("executing", copy_command)
        exit_code, output = container.exec_run(copy_command)
        print(output.decode("utf-8"))

    else:
        print(vul_id, "didn't compile!")
    return bool_compiled, bool_test_passed


def get_cve_id_and_failed_test_details(dir_path):
    path_testing_results_json_file = dir_path.joinpath("testing_results.json")
    dict_failed_tests = {}
    cve_id = ""
    print("looking for", path_testing_results_json_file)
    if os.path.exists(path_testing_results_json_file):
        file_testing_results_json = open(path_testing_results_json_file)
        content_testing_results_json_file = json.load(file_testing_results_json)
        file_testing_results_json.close()
        cve_id = content_testing_results_json_file["cve_id"]
        failures = content_testing_results_json_file["tests"]["failures"]
        for failure in failures:
            failed_test = failure["test_class"] + "#" + failure["test_method"]
            failure_name = failure["failure_name"]
            if failed_test not in dict_failed_tests:
                dict_failed_tests[failed_test] = failure_name
    return cve_id, dict_failed_tests


def get_intersection_and_ochiai(broken_tests_by_vuln, broken_tests_by_mutant):
    if len(broken_tests_by_vuln) == 0 or len(broken_tests_by_mutant) == 0:
        return "\"\"", 0
    intersection = []
    for broken_test_by_vuln in broken_tests_by_vuln:
        if broken_test_by_vuln in broken_tests_by_mutant:
            intersection.append(broken_test_by_vuln)
    if len(intersection) == 0:
        return "\"\"", 0
    prod = len(broken_tests_by_vuln) * len(broken_tests_by_mutant)
    ochiai = round((len(intersection) / math.sqrt(prod)), 4)

    string_intersection = "\""
    for interesection_test in intersection:
        if string_intersection == "\"":
            string_intersection = string_intersection + interesection_test
        else:
            string_intersection = string_intersection + "," + interesection_test
    string_intersection = string_intersection + "\""
    return string_intersection, ochiai


def traverse_dictionary_get_failed_tests_with_failures(dict_failed_tests):
    failed_tests = ""
    failures = ""
    for failed_test in dict_failed_tests:
        if failed_tests == "":
            failed_tests = failed_test
            failures = dict_failed_tests[failed_test]
        else:
            failed_tests = failed_tests + "," + failed_test
            failures = failures + "," + dict_failed_tests[failed_test]
    return failed_tests, failures


def get_vuln_coupling_analysis_results(dict_failed_tests_by_vuln, dict_failed_tests_by_mutant):
    keys_failed_tests_by_vuln = set(dict_failed_tests_by_vuln.keys())
    keys_failed_tests_by_mutant = set(dict_failed_tests_by_mutant.keys())
    if len(keys_failed_tests_by_mutant) == 0:
        return keyword_mutant_not_killed
    if dict_failed_tests_by_vuln == dict_failed_tests_by_mutant:
        return keyword_strong_substitution
    if keys_failed_tests_by_vuln == keys_failed_tests_by_mutant:
        return keyword_test_substitution
    shared_keys_failed_tests = keys_failed_tests_by_vuln.intersection(keys_failed_tests_by_mutant)
    if len(shared_keys_failed_tests) == 0:
        return keyword_no_substitution
    if len(keys_failed_tests_by_mutant) > len(shared_keys_failed_tests):
        if len(shared_keys_failed_tests) == len(keys_failed_tests_by_vuln):
            for key in shared_keys_failed_tests:
                if dict_failed_tests_by_mutant[key] != dict_failed_tests_by_vuln[key]:
                    return keyword_test_substitution_with_add_tests_failed
            return keyword_strong_substitution_with_add_tests_failed
        else:
            for key in shared_keys_failed_tests:
                if dict_failed_tests_by_mutant[key] != dict_failed_tests_by_vuln[key]:
                    return keyword_partial_test_substitution_with_add_tests_failed
            return keyword_partial_substitution_with_add_tests_failed
    else:
        for key in shared_keys_failed_tests:
            if dict_failed_tests_by_mutant[key] != dict_failed_tests_by_vuln[key]:
                return keyword_partial_test_substitution
        return keyword_partial_substitution


def get_mutant_vulnerability_comparison_scores(changed_file_path, mutant_id, dict_failed_tests_by_vuln):
    did_mutant_compile = False
    did_tests_fail = False
    imitates_vuln = False
    ochiai = 0
    failed_tests_intersection = "\"\""

    bool_compiled = get_compilation_results(changed_file_path.joinpath(mutant_id))
    bool_test_passed = get_test_results(changed_file_path.joinpath(mutant_id))

    failed_tests_vuln, failures_vuln = traverse_dictionary_get_failed_tests_with_failures(dict_failed_tests_by_vuln)
    failed_tests_vuln = "\"" + failed_tests_vuln + "\""
    failures_vuln = "\"" + failures_vuln + "\""

    failed_tests_mutant = ""
    failures_mutant = ""
    vuln_coupling_result = keyword_compilation_error

    if bool_compiled is True:
        did_mutant_compile = True
        if bool_test_passed is False:
            did_tests_fail = True
            cve_id, dict_failed_tests_by_mutant = get_cve_id_and_failed_test_details(changed_file_path.joinpath(mutant_id))
            if set(dict_failed_tests_by_mutant.keys()) == set(dict_failed_tests_by_vuln.keys()):
                print(mutant_id, "triggers the same tests triggered by the vulnerability!")
                imitates_vuln = True
            failed_tests_intersection, ochiai = get_intersection_and_ochiai(set(dict_failed_tests_by_vuln.keys()),
                                                                            set(dict_failed_tests_by_mutant.keys()))

            failed_tests_mutant, failures_mutant = traverse_dictionary_get_failed_tests_with_failures(
                dict_failed_tests_by_mutant)
            failed_tests_mutant = "\"" + failed_tests_mutant + "\""
            failures_mutant = "\"" + failures_mutant + "\""

            vuln_coupling_result = get_vuln_coupling_analysis_results(dict_failed_tests_by_vuln,
                                                                      dict_failed_tests_by_mutant)
        else:
            vuln_coupling_result = keyword_mutant_not_killed

    return (did_mutant_compile, did_tests_fail, imitates_vuln, ochiai, failed_tests_intersection, failed_tests_mutant,
            failures_mutant, failed_tests_vuln, failures_vuln, vuln_coupling_result)


def analyze_mutants_simulations_and_get_analysis():
    analysis_dir = "vul4j/analysis"

    if os.path.exists(analysis_dir) is False:
        os.mkdir(analysis_dir)
    df_analysis_csv = pd.DataFrame(
        columns=['vul_id', 'cve_id', 'class', 'mut_id', 'did_mutant_compile', 'did_tests_fail',
                 'imitates_vuln', 'ochiai', 'failed_tests_intersection', 'failed_tests', 'failures'])
    for vul_id in os.listdir('vul4j/code_dir'):
        if os.path.exists(analysis_dir + "/" + vul_id + "_analysis_file.csv"):
            df_vul_id_analysis_csv = pd.read_csv(analysis_dir + "/" + vul_id + "_analysis_file.csv")
            df_analysis_csv = pd.concat([df_analysis_csv, df_vul_id_analysis_csv], ignore_index=True)
            continue

        df_vul_id_analysis_csv = pd.DataFrame(
            columns=['vul_id', 'cve_id', 'class', 'mut_id', 'did_mutant_compile', 'did_tests_fail',
                     'imitates_vuln', 'ochiai', 'failed_tests_intersection', 'failed_tests', 'failures'])

        mutated_code_path = Path("vul4j/code_dir/" + vul_id + "/VUL4J/mutated_code/")
        if not mutated_code_path.exists():
            print(mutated_code_path, "not exist")
            continue
        cve_id, dict_failed_tests_by_vuln = get_cve_id_and_failed_test_details(Path("vul4j/code_dir/" + vul_id
                                                                                    + "/VUL4J/test_result/"))
        """if len(dict_failed_tests_by_vuln) == 0:
            print("NO FAILED TESTS")
            continue"""
        model_subfolder_path = mutated_code_path.joinpath("gemini", "prompt2")
        if model_subfolder_path.exists():
            for changed_file_dir in os.listdir(model_subfolder_path):
                changed_file_path = model_subfolder_path.joinpath(changed_file_dir)

                for mutant_id in os.listdir(changed_file_path):
                    if os.path.isdir(changed_file_path.joinpath(mutant_id)) is False:
                        continue
                    print("\nanalyzing vul_id:", vul_id, "| class:", changed_file_dir, "| mut_id:", mutant_id)
                    (did_mutant_compile, did_tests_fail, imitates_vuln, ochiai, failed_tests_intersection,
                     failed_tests, failures, failed_tests_vuln, failures_vuln, vuln_coupling_result) = \
                        get_mutant_vulnerability_comparison_scores(changed_file_path, mutant_id,
                                                                   dict_failed_tests_by_vuln)
                    data = {
                        'vul_id': "\"" + vul_id + "\"",
                        'cve_id': "\"" + cve_id + "\"",
                        'class': "\"" + changed_file_dir + "\"",
                        'mut_id': mutant_id,
                        'did_mutant_compile': did_mutant_compile,
                        'did_tests_fail': did_tests_fail,
                        'imitates_vuln': imitates_vuln,
                        'ochiai': ochiai,
                        'failed_tests_intersection': failed_tests_intersection,
                        'failed_tests': failed_tests,
                        'failures': failures,
                        'failed_tests_vuln': failed_tests_vuln,
                        'failures_vuln': failures_vuln,
                        'vuln_coupling_result': vuln_coupling_result
                    }
                    new_row = pd.DataFrame([data])
                    df_vul_id_analysis_csv = pd.concat([new_row, df_vul_id_analysis_csv], ignore_index=True)

                    data = {'vul_id': "\"" + vul_id + "\"",
                     'cve_id': "\"" + cve_id + "\"",
                     'class': "\"" + changed_file_dir + "\"",
                     'mut_id': mutant_id,
                     'did_mutant_compile': did_mutant_compile,
                     'did_tests_fail': did_tests_fail,
                     'imitates_vuln': imitates_vuln,
                     'ochiai': ochiai,
                     'failed_tests_intersection': failed_tests_intersection,
                     'failed_tests': failed_tests,
                     'failures': failures,
                     'failed_tests_vuln': failed_tests_vuln,
                     'failures_vuln': failures_vuln,
                     'vuln_coupling_result': vuln_coupling_result}
                    new_row = pd.DataFrame([data])
                    df_analysis_csv = pd.concat([new_row, df_analysis_csv], ignore_index=True)

                if len(df_vul_id_analysis_csv) > 0:
                    print("writing", analysis_dir + "/" + vul_id + "_analysis_file.csv")
                    df_vul_id_analysis_csv.to_csv(analysis_dir + "/" + vul_id + "_analysis_file.csv", index=False)

    print("writing all_analysis_csv.csv in", analysis_dir)
    df_analysis_csv.to_csv(analysis_dir + "/" + "all_analysis_csv.csv", index=False)
    return df_analysis_csv


def plot(df_analysis_csv):
    if os.path.exists("vul4j/analysis/chatgpt_prompt2/plot_ochiai.pdf") == False:
        df = df_analysis_csv.loc[
            (df_analysis_csv['did_mutant_compile'] == True) & (df_analysis_csv['did_tests_fail'] == True)]
        df = df.sort_values(by='cve_id', ascending=True)
        rcParams['figure.figsize'] = 15, 7
        f = plt.figure(1)
        ax = sns.boxplot(x=df["cve_id"], y=df["ochiai"])
        ax.set_xticklabels(ax.get_xticklabels(), rotation=70)
        plt.xlabel('CVE', fontsize=16);
        plt.ylabel('Ochiai', fontsize=16);
        plt.tick_params(axis='both', which='major', labelsize=12)
        plt.tight_layout()
        plt.savefig("vul4j/analysis/plot_ochiai.pdf")


def plot_coupling(df_analysis_csv):
    if os.path.exists("vul4j/analysis/chatgpt_prompt2/plot_coupling.pdf") == False:
        exclude_categories = [keyword_compilation_error, keyword_mutant_not_killed, keyword_no_substitution]
        data = df_analysis_csv[~df_analysis_csv['vuln_coupling_result'].isin(exclude_categories)]

        category_order = [keyword_strong_substitution, keyword_strong_substitution_with_add_tests_failed,
                          keyword_test_substitution, \
                          keyword_test_substitution_with_add_tests_failed, keyword_partial_substitution, \
                          keyword_partial_substitution_with_add_tests_failed, keyword_partial_test_substitution, \
                          keyword_partial_test_substitution_with_add_tests_failed]
        data['vuln_coupling_result'] = pd.Categorical(
            data['vuln_coupling_result'], categories=category_order, ordered=True)

        grouped_data = data.groupby(['cve_id', 'vuln_coupling_result']).size().unstack(fill_value=0)
        grouped_data_percentage = grouped_data.div(grouped_data.sum(axis=1), axis=0) * 100

        grouped_data_percentage = grouped_data_percentage.sort_values(by='cve_id', ascending=False)
        ax = grouped_data_percentage.plot(kind='barh', stacked=True, figsize=(10, 7))
        plt.xlabel('Coupling Mutants(%)')
        plt.ylabel('CVE')

        category_labels = {keyword_strong_substitution: "Strong Coupling",
                           keyword_strong_substitution_with_add_tests_failed: "Strong Coupling + Additional",
                           keyword_test_substitution: "Test Coupling",
                           keyword_test_substitution_with_add_tests_failed: "Test Coupling + Additional",
                           keyword_partial_substitution: "Partial Coupling",
                           keyword_partial_substitution_with_add_tests_failed: "Partial Coupling + Additional",
                           keyword_partial_test_substitution: "Partial Test Coupling",
                           keyword_partial_test_substitution_with_add_tests_failed: "Partial Test Coupling + Additional"}
        handles, labels = ax.get_legend_handles_labels()
        custom_labels = [category_labels.get(label, label) for label in labels]
        ax.legend(handles, custom_labels, title='Coupling Categories', loc='upper center', bbox_to_anchor=(0.4, -0.10),
                  ncol=3)
        plt.grid(axis='x', linestyle='--', alpha=0.6)
        plt.tight_layout()
        plt.savefig("vul4j/analysis/plot_coupling.pdf")
        plt.show()


def plot_venn_vulnerability (data):
    if os.path.exists("vul4j/analysis/chatgpt_prompt2/plot_venn.pdf") == False:
        fig, axes = plt.subplots(5, 1, figsize=(6, 15))

        set1 = set(data[(data['vuln_coupling_result'] == keyword_strong_substitution)
                       | (data['vuln_coupling_result'] == keyword_strong_substitution_with_add_tests_failed)
                       | (data['vuln_coupling_result'] == keyword_test_substitution)
                       | (data['vuln_coupling_result'] == keyword_test_substitution_with_add_tests_failed)
                       | (data['vuln_coupling_result'] == keyword_partial_substitution)
                       | (data['vuln_coupling_result'] == keyword_partial_substitution_with_add_tests_failed)
                       | (data['vuln_coupling_result'] == keyword_partial_test_substitution)
                       | (data['vuln_coupling_result'] == keyword_partial_test_substitution_with_add_tests_failed)]['cve_id'])
        set2 = set(data['cve_id'])
        venn2([set1, set2], ("All Coupling", "All Vulnerabilities"), ax=axes[0])

        set1 = set(data[data['vuln_coupling_result'] == keyword_strong_substitution]['cve_id'])
        set2 = set(data[data['vuln_coupling_result'] == keyword_strong_substitution_with_add_tests_failed]['cve_id'])
        set3 = set(data['cve_id'])
        venn3([set1, set2, set3], ("Strong Coupling", "Strong Coupling + Additional", "All Vulnerabilities"), ax=axes[1])

        set1 = set(data[data['vuln_coupling_result'] == keyword_test_substitution]['cve_id'])
        set2 = set(data[data['vuln_coupling_result'] == keyword_test_substitution_with_add_tests_failed]['cve_id'])
        set3 = set(data['cve_id'])
        venn3([set1, set2, set3], ("Test Coupling", "Test Coupling + Additional", "All Vulnerabilities"), ax=axes[2])

        set1 = set(data[data['vuln_coupling_result'] == keyword_partial_substitution]['cve_id'])
        set2 = set(data[data['vuln_coupling_result'] == keyword_partial_substitution_with_add_tests_failed]['cve_id'])
        set3 = set(data['cve_id'])
        venn3([set1, set2, set3], ("Partial Coupling", "Partial Coupling + Additional", "All Vulnerabilities"), ax=axes[3])

        set1 = set(data[data['vuln_coupling_result'] == keyword_partial_test_substitution]['cve_id'])
        set2 = set(data[data['vuln_coupling_result'] == keyword_partial_test_substitution_with_add_tests_failed]['cve_id'])
        set3 = set(data['cve_id'])
        venn3([set1, set2, set3], ("Partial Test Coupling", "Partial Test Coupling + Additional", "All Vulnerabilities"), ax=axes[4])
        plt.tight_layout()
        plt.savefig("vul4j/analysis/plot_venn.pdf")
        plt.show()


def compile_vul(container, vul_id):
    destination_path = "vul4j/code_dir/" + vul_id + "/VUL4J/compile_result"
    if not os.path.exists(destination_path):
        os.mkdir(destination_path)
    elif os.path.exists(destination_path + "/compile.log") and os.path.exists(destination_path + "/compile_result.txt"):
        return

    command_to_execute = ["vul4j", "compile", "-d", "/data/code_dir/" + vul_id]
    print("executing", command_to_execute)
    exit_code, output = container.exec_run(command_to_execute)
    print(output.decode("utf-8"))

    destination_path = str(destination_path).replace("vul4j", "data")
    copy_command = ["cp", "/data/code_dir/" + vul_id + "/VUL4J/compile.log", destination_path]
    print("executing", copy_command)
    exit_code, output = container.exec_run(copy_command)
    print(output.decode("utf-8"))

    copy_command = ["cp", "/data/code_dir/" + vul_id + "/VUL4J/compile_result.txt", destination_path]
    print("executing", copy_command)
    exit_code, output = container.exec_run(copy_command)
    print(output.decode("utf-8"))


def test_vul(container, vul_id):
    destination_path = "vul4j/code_dir/" + vul_id + "/VUL4J/test_result"
    if os.path.exists(destination_path) is False:
        os.mkdir(destination_path)
    elif os.path.exists(destination_path + "/testing.log") and os.path.exists(destination_path + "/testing_results.json"):
        return

    command_to_execute = ["vul4j", "test", "-d", "/data/code_dir/" + vul_id]
    print("executing", command_to_execute)
    container.exec_run(command_to_execute)

    destination_path = str(destination_path).replace("vul4j", "data")
    copy_command = ["cp", "/data/code_dir/" + vul_id + "/VUL4J/testing.log", destination_path]
    print("executing", copy_command)
    exit_code, output = container.exec_run(copy_command)
    print(output.decode("utf-8"))

    copy_command = ["cp", "/data/code_dir/" + vul_id + "/VUL4J/testing_results.json", destination_path]
    print("executing", copy_command)
    exit_code, output = container.exec_run(copy_command)
    print(output.decode("utf-8"))


def main():
    base_directory = Path('vul4j/code_dir')
    if not base_directory.exists():
        base_directory.mkdir(parents=True, exist_ok=True)

    container = run_docker_container()
    checkout(container)

    for vul_id in os.listdir(base_directory):
        print("\n\nVulnerabilities to be analysed: ", vul_id)
        path_vuln = base_directory.joinpath(vul_id)

        compile_vul(container, vul_id)
        test_vul(container, vul_id)

        mutated_path = path_vuln.joinpath("VUL4J/mutated_code")
        if mutated_path.exists() is False:
            mutated_path.mkdir(parents=True, exist_ok=True)

        vuln_directory = path_vuln.joinpath("VUL4J/vulnerable")
        fixed_directory = path_vuln.joinpath('VUL4J/human_patch')
        for file in os.listdir(vuln_directory):
            if not file.endswith('.java'):
                continue
            file_name = file.replace(".java", "")
            # il fixed del progetto 11 non è corretto perchè legge una eccezione il problema è in compare classes
            fixed_methods, vuln_methods = compare_classes(vuln_directory.joinpath(file), fixed_directory.joinpath(file))
            if fixed_methods and vuln_methods:
                for fixed, vuln in zip(fixed_methods, vuln_methods):
                    print()
                    generate_mutants(fixed, vuln, file_name, fixed_directory.joinpath(file), vul_id, container)
            else:
                print("There are no differences between two classes.")


    df_analysis_csv = analyze_mutants_simulations_and_get_analysis()
    #plot(df_analysis_csv)
    #plot_coupling(df_analysis_csv)
    #plot_venn_vulnerability(df_analysis_csv)


main()
