#!/bin/python3
"""Identify functions by input output behaviour.

"""
import angr
import logging
import datetime
import sys
import glob
import os
import json
import math

import angr.factory
import angr.sim_type

from itertools import permutations

DB_FILE = "C:\\Users\\antoi\\Documents\\Ecole\\Memoire\\Code\\DB.json"

HOOK_FILE = "C:\\Users\\antoi\\Documents\\Ecole\\Memoire\\Code\\hooks.json"

# TODO add function lengths to results + modify SEMA again to match what i just did
# --> just need to update the values of dict

class FunctionIdentifyer():
    """Identify functions by analyzing the input output behaviour."""

    def __init__(self,
                 logfile_name=str(datetime.datetime.now().strftime("%Y-%m-%#d--%Hh%Mmin%Ss")),
                 sample="" 
                ) -> None:
        """Initialize and set logging."""
        # Only search for functions with the name self.name
        #
        self.skip_by_name = False
        #self.name = "generate_domain"
        # Skip all samples but a the specified one. = Analyze only the one specified sample.
        # By default, look inside all samples
        self.skip_all_samples_but_this = sample
        # Look at the prototype of the function and analyze only if it is correct.
        self.ignore_prototype_info = False
        # If angr can not find the prototype analyze the function if set to True.
        self.analyze_if_unknown_prototype = True

        # Set log file name
        self.logfile_name = logfile_name

        # Set logging.
        logging.basicConfig()
        # Get the default logger for this name
        self.logger = logging.getLogger(__name__)
        file_handler_details = logging.FileHandler(f"logs\\analysis_details_{logfile_name}.log")
        file_handler_details.setFormatter(logging.Formatter("%(asctime)s : %(message)s"))
        self.logger.addHandler(file_handler_details)
        self.logger.setLevel(logging.DEBUG)
        # Disable/Enable logging for angr
        log_things = ["angr", "pyvex", "claripy", "cle"]
        for log in log_things:
            logger_angr = logging.getLogger(log)
            logger_angr.setLevel(logging.ERROR)
            # logger_angr.disabled = False
            # logger_angr.propagate = False
            logger_angr.addHandler(file_handler_details)
        # Make a new logger for the results
        self.logger_results = logging.getLogger("results")
        file_handler_results = logging.FileHandler(f"logs\\analysis_results_{logfile_name}.log")
        file_handler_results.setFormatter(logging.Formatter("%(asctime)s : %(message)s"))
        self.logger_results.addHandler(file_handler_results)
        self.logger_results.setLevel(logging.DEBUG)

        # Register custom angr types
        angr_type_registration()

    def input_generation(self, candidates: dict, angr_project: angr.Project, return_type=None, func_name=None):
        """
        Generate input of candidates to use when trying to call the function with a Callable

        Parameters
        ----------
        candidates : dict
            Dictionary of candidates for which input needs to be generated
        angr_project : angr.Project
            The current angr project
        return_type : str | None
            The return type of the function if extracted otherwise None
        func_name : str | None
            The name of the functionality for which we want to generate inputs if we want for only one. Otherwise, set to None

        Returns
        -------
        dict[str, list[Any]]
            Dictionary of the inputs with key = candidate name and value = list of inputs
        
        """

        f_input = {}

        # Deactivate log if multiple functionalities to try
        log = False
    
        for c_name, c_internals in candidates.items():

            # Activate logging when only 1 functionality
            if func_name:
                log = True
                # If we are trying to generate inputs for a specific functionality
                # => Just skip to that one
                if func_name != c_name:
                    continue
            
            if return_type:
                if c_internals['output_type'] != return_type:
                    self.logger.debug(f"Skipping candidate {c_name}, because {c_internals['output_type']} different from convention return type {return_type}.")
                    continue
            else:
                self.logger.debug(f"{c_name} is a candidate")

                # Create entry for current candidate
                f_input[c_name] = []
                # Indexes
                arg_i = 0
                specific_type_i = 0

                for arg in c_internals['input']:
                    self.logger.info(f"Processing argument {arg} at position {arg_i}")
                    # Check if current argument is a specific type
                    if bool(c_internals['specific_types'][arg_i]) == True:

                        self.logger.info(f"{c_name} has struct, reconstructing.")
                        
                        # Create specific type value
                        st = angr.sim_type.ALL_TYPES[arg]
                        stv = angr.sim_type.SimStructValue(st, values=c_internals['specific_type_value'][specific_type_i])
                        pstv = angr_project.factory.callable.PointerWrapper(stv)

                        # Log value of structure
                        if log:
                            self.logger.debug(f"Struct value : {pstv.value}")
                        
                        f_input[c_name].append(pstv)
                        
                        specific_type_i += 1
                    else:
                        f_input[c_name].append(arg)

                    arg_i += 1


        permuted_inputs = {}
        # generate permutations
        for c_name, c_input in f_input.items():
            # If more than 1 input, use permutations to generate all potential combinations
            # Generate a key + input for each
            same_name_avoider = 0
            if  len(c_input) > 1:
                # Get every permutation
                permutation_list = list(permutations(c_input))
                # Add all permutations to dict and duplicate key names by generating it with a counter
                for input_permutation in permutation_list:
                    permuted_inputs[f'{c_name}_{same_name_avoider}'] = input_permutation
                    same_name_avoider += 1
            else:
                permuted_inputs[c_name] = c_input

        return permuted_inputs
    
    def candidate_generation(self, db_data: dict, error: bool, args: str):
        """
        Generate interesting candidates

        Parameters
        ----------
        db_data : dict
            Dictionary of functionalities data
        error : bool
            Boolean describing if function prototype was extracted
        args : str
            String of the types of arguments of functionality

        Returns
        -------
        dict[name, internals], list[str]
            Dictionary of candidates with their names as keys and internals as values\n
            List of string describing the parameters of each candidate
        """

        parent_list = []
        
        #If error to False => only get specific functions from DB.
        if not error and error != None:
            self.logger.debug(f"Function convention retrieved. Looking for potential match.")
            # Count number of arguments
            # # arguments = #',' + 1 because of the construction of the argument types
            nb_args = args.count(',') + 1
            # If argument str is not empty but nb of argument = 0 => set nb of arg to 1.
            # => because of construction of argument str
            if args != "" and nb_args == 0:
                nb_args = 1
            
            try : 
                # Dict of functions matching the description
                input_matches = db_data[str(nb_args)][args]

                # Candidate parameter list needs to take into account both
                # 1) The number of candidates
                # 2) The number of permutations of said candidates
                # for each candidate, compute its potential number of permutation
                # then add args as much times as there are permutations

                # In this case, all candidates have the same args structure.
                # We loop on all candidates and for each append a number of
                # parameter equal to its number of permutation
                nb_permutation = math.factorial(nb_args)
                for _ in range (len(input_matches.keys())):
                    for _ in range(nb_permutation):
                        parent_list.append(args)
            except KeyError as ke:
                self.logger.debug(f"No functionality with prototype - args number : {nb_args} & args : {args}")

                # No value matching this function in DB
                return {}, []
            
        else :
            self.logger.debug(f"Function convention not found. Brute forcing for potential match.")
            # All functionalities might be a match
            input_matches = {} 
            for first_key in db_data:
                if first_key.isdigit():
                    for param in db_data[first_key]:
                        for func, func_internals in db_data[first_key][param].items():
                            input_matches[func] = func_internals
                            # Here, each candidate has a different args structure.
                            # for each parameter, we add a number equal to its own number of permutation
                            for _ in range(math.factorial(int(first_key))):
                                parent_list.append(param)
                        
        return input_matches, parent_list

    def output_comparison(self, expected_output, expected_output_type: str, output, c_name: str, func_name: str, func_addr, result_state):
        """
        Returns True if the output of the candidate matches the one of the function name

        Resolves the output to a concrete value

        Parameters
        ----------
        expected_output : Any
            Expected output value
        expected_output_type : str
            Type of the expected_output
        output : Any
            Actual output
        c_name : str
            Name of the candidate
        func_name : str
            Name of the analyzed function
        func_addr
            Address of the analyzed function
        result_state
            Result state of the Callable function after execution

        Returns
        -------
        bool
            True if expected_output matches output
 
        """
        
        #self.logger.info(f"Output comparison\n\
        #                    Expected output: {expected_output}\n\
        #                    Expected output type: {expected_output_type}\n\
        #                    Actual output : {output}\n\
        #                    Functionality candidate name: {c_name}\n\
        #                    Function name & address : {func_name} & {func_addr}\n\
        #                    Result state : {result_state}\n\
        #                    Result state.mem[output]: {result_state.mem[output]}\n\
        #                    ")

        # Output type does not match expected type
        if expected_output_type == "String":
            ret_bytes = result_state.mem[output].string.concrete
            self.logger.debug(f"Function '{func_name}' with '{c_name}', at {func_addr} has return bytes: {ret_bytes}")
            ret_val = ret_bytes.decode("utf-8")
            self.logger.debug(f"Function '{func_name}' with '{c_name}', at {func_addr} has return value: {ret_val}")
            # Convert expected output to str
            expected_output = str(expected_output)

        elif expected_output_type == "int":
            ret_val = result_state.solver.eval(output)
            self.logger.debug(f"Function '{func_name}' with '{c_name}', at {func_addr} has return value: {ret_val}")
            # Convert expected output to int
            expected_output = int(expected_output)
        
        #TODO more use cases

        if (ret_val == expected_output):
            return True
        
        return False

    def analyze(self, full_analysis=True, func_name="", arg_nb=0, arg_str="", function_name=""):
        """
        Search for and analyze the samples.
        
        Parameters
        ----------
        full_analysis : bool
            Analyze all functions within a sample
        func_name : str
            Name of the functionality to look for
        arg_nb : int
            Number of argument of functionality
        arg_str : str
            String of the types of arguments of functionality
        function_name : str
            Name of the function to analyze

        """
        # Set log config
        self.logger.info("#"*80)
        self.logger.info(f"angr: {angr.__version__}")
        self.logger.info(f"angr: {sys.version_info}")
        self.logger.info("#"*80)
        now = datetime.datetime.now()
        self.logger.info(f"Start: {now}")

        # Log if full analysis or
        self.logger.info("*"*80)
        self.logger.info(f"Full Analysis: {full_analysis}")
        if full_analysis and func_name != "":
            self.logger.info(f"Functionality Analysis : {func_name}")
        self.logger.info("*"*80)
        # Analyze the samples
        samples = glob.glob("./samples/*", recursive=True)
        samples.sort()
        for sample in samples:
            if self.skip_all_samples_but_this != "":
                if sample != self.skip_all_samples_but_this:
                    self.logger_results.debug(f"Skipping analysis of '{sample}', because it is not {self.skip_all_samples_but_this}.")
                    continue
            if (os.path.isdir(sample)):
                continue

            self.logger_results.debug(f"Starting analysis of '{sample}'")

            # Analyze sample and check if any known function in it
            if full_analysis and func_name == "":
                candidates = self.full_analyze_sample(sample)
                self.logger_results.warning(f"Fully analyzed sample '{sample}' and got {candidates}")

            # Look in the program for a specific functionality with func_name
            elif full_analysis and func_name != "":
                candidates = self.analyze_sample(sample, arg_nb, arg_str, func_name)
                self.logger_results.warning(f"Analyzed sample '{sample}' and got {candidates}")

            # Try to find a functionality in the DB matching function with function_name
            elif not full_analysis and function_name != "":
                self.analyze_function(sample, function_name)

            # Log that no analysis happened
            else:
                self.logger_results.error(f"Analysis not possible.\n'Full analysis': {full_analysis}\n'Function name': {function_name}")

        write_hooks_json(candidates, HOOK_FILE)

        self.logger.info("*"*80)
        now = datetime.datetime.now()
        self.logger.info(f"End: {now}")

    def analyze_sample(self, path: str, arg_nb: int, arg_str:str, func_name:str):
        """Analyze all the functions of a sample and look for a specific argument-return value behaviour.

        Parameters
        ---------
        path: str
            Path and name of the sample.
        arg_nb : int
            Number of argument of functionality
        arg_str : str
            String of the types of arguments of functionality
        func_name : str
            Name of the functionality in the DB

        Returns
        -------
        dict[int, str]
            Dict of the addresses and names of the candidate functions.
        """
        self.logger.debug(f"Starting analysis of {path}")
        p = angr.Project(path, load_options={"auto_load_libs": False}, use_sim_procedures=True)
        cfg = p.analyses.CFGFast()

        try : 
            with open(DB_FILE) as f:
                db_data = json.load(f)
        except OSError as ex:
            self.logger.exception(f"Problem when trying to open DB file. Exception: {ex}")
        except Exception as ex:
            self.logger.exception(f"Exception: {ex}") 

        candidate_functions = {}

        # Create expected input, output and prototype

        expected_input = self.input_generation(db_data[str(arg_nb)][arg_str], p, func_name=func_name)
        expected_output = get_expected_output_db(db_data, arg_nb, arg_str, func_name)
        prototype = get_expected_prototype_db(db_data, arg_nb, arg_str, func_name)
        user_hook = get_hook(db_data, arg_nb, arg_str, func_name)

        #####

        func_len = len(p.kb.functions.values())
        current_func = 0

        # Analyze all functions
        for func in p.kb.functions.values():

            current_func = current_func + 1
            self.logger.info(f"[{str(current_func)}/{str(func_len)}] Analyzing Function '{func.name}', at {hex(func.addr)}")

            if self.skip_by_name and func.name != self.name:
                self.logger.debug(f"[{str(current_func)}/{str(func_len)}] Skipping Function '{func.name}', at {hex(func.addr)}")
                continue

            if not self.ignore_prototype_info:
                convention = p.analyses.CallingConvention(func, cfg=cfg, analyze_callsites=True)

                error = False
                if convention is None:
                    self.logger.error(f"Could not get get calling convention of function {func.name} at {hex(func.addr)}")
                    error = True
                if convention.prototype is None:
                    self.logger.error(f"Could not get get prototype of function {func.name} at {hex(func.addr)}")
                    error = True
              
                if not error:
                    if len(convention.prototype.args) != arg_nb:
                        self.logger.info(f"[{str(current_func)}/{str(func_len)}] Skipping Function '{func.name}', at {hex(func.addr)}, because of arguments")
                        continue

                if error and not self.analyze_if_unknown_prototype:
                    self.logger.error(f"Skipping {func.name} at {hex(func.addr)} because of analyze_if_unknown_prototype = {self.analyze_if_unknown_prototype}.")
                    continue
                # Retrieving types of arguments + type of return value
                elif not error:
                    args = ""
                    for i, register in enumerate(convention.cc.arg_locs(convention.prototype)):
                        typ = convention.prototype.args[i]
                        if (args == ""):
                            args = typ.c_repr()
                        else:
                            args = args + ", " + typ.c_repr()
                    self.logger.debug(f"Function {func.name} at {hex(func.addr)} has args {args}")
                    self.logger.debug(f"Function {func.name} at {hex(func.addr)} has return type :  {convention.prototype.returnty}")
                else:
                    self.logger.debug(f"Could not check the args and return value but moving on because of self.analyze_if_unknown_prototype.")

            # Might have multiple potential inputs if more than 1 parameter (permutations)
            for c_input in expected_input.values():
                try:
                    # Simulation preparation
                    call_state = p.factory.call_state(func.addr, *c_input, prototype=prototype, mode="tracing", add_options={angr.options.CONCRETIZE}, remove_options={angr.options.SIMPLIFY_MEMORY_WRITES, angr.options.SIMPLIFY_MEMORY_READS, angr.options.UNICORN})
                    check_func = p.factory.callable(func.addr, prototype=prototype, concrete_only=True, base_state=call_state)

                    self.logger.debug(f"Function {func.name} at {hex(func.addr)}: Running angr callable with concrete arguments.")

                    # Actual simulation
                    ret_val = check_func(*c_input)

                    self.logger.debug(f"Function {func.name} at {hex(func.addr)} has return value: {ret_val}")

                    comparison = self.output_comparison(expected_output, db_data[str(arg_nb)][arg_str][func_name]['output_type'], ret_val, func_name, func.name, func.addr, check_func.result_state)
                        
                    if comparison:
                        self.logger_results.warning(f"CANDIDATE FUNCTION FOUND '{func.name}'!")
                        candidate_functions[func.addr] = [func.name, func_name, user_hook]
                        return candidate_functions
                        # We can return the dict here. Returning implies that we only know 1 potential position
                    else:
                        self.logger.warning(f"Not a candidate function: '{func.name}' at {hex(func.addr)}, has return vale: {ret_val}")

                except UnicodeDecodeError as ex:
                    self.logger.exception(f"Could not decode the return value {ret_val} of function {func.name} at {hex(func.addr)}. Because of {ex}")
                except Exception as ex:
                    self.logger.exception(f"Exception: {ex}")

        self.logger.warning(f"Candidate functions: {candidate_functions}")
        return candidate_functions

    def full_analyze_sample(self, path: str):
        """
        Analyze all the functions of a sample and check if any function matches a known argument-return value behavior.

        Parameters
        ---------
        path: str
            Path and name of the sample.
        """
        self.logger.debug(f"Starting analysis of {path}")
        p = angr.Project(path, load_options={"auto_load_libs": False}, use_sim_procedures=True)
        cfg = p.analyses.CFGFast()

        #####

        results = {}

        try : 
            with open(DB_FILE) as f:
                db_data = json.load(f)
        except OSError as ex:
            self.logger.exception(f"Problem when trying to open DB file. Exception: {ex}")
        except Exception as ex:
            self.logger.exception(f"Exception: {ex}") 

        func_len = len(p.kb.functions.values())
        current_func = 0

        # Analyze all functions
        for func in p.kb.functions.values():

            current_func = current_func + 1
            self.logger.info(f"[{str(current_func)}/{str(func_len)}] Analyzing Function '{func.name}', at {hex(func.addr)}")

            if self.skip_by_name and func.name != self.name:
                self.logger.debug(f"[{str(current_func)}/{str(func_len)}] Skipping Function '{func.name}', at {hex(func.addr)}")
                continue

            error = None
            args = ""
            return_type = None
            if not self.ignore_prototype_info:
                convention = p.analyses.CallingConvention(func, cfg=cfg, analyze_callsites=True)

                error = False
                if convention is None:
                    self.logger.error(f"Could not get get calling convention of function {func.name} at {hex(func.addr)}")
                    error = True
                if convention.prototype is None:
                    self.logger.error(f"Could not get get prototype of function {func.name} at {hex(func.addr)}")
                    error = True

                if error and not self.analyze_if_unknown_prototype:
                    self.logger.error(f"Skipping {func.name} at {hex(func.addr)} because of analyze_if_unknown_prototype")
                    continue
                elif not error:
                    args = ""
                    for i, register in enumerate(convention.cc.arg_locs(convention.prototype)):
                        typ = convention.prototype.args[i]
                        if (args == ""):
                            args = typ.c_repr()
                        else:
                            args = args + ", " + typ.c_repr()
                    self.logger.debug(f"Function {func.name} at {hex(func.addr)} has args {args}")
                    return_type = convention.prototype.returnty
                    self.logger.debug(f"Function {func.name} at {hex(func.addr)} has return type {return_type}")

                else:
                    self.logger.debug(f"Could not check the args and return value but moving on because of self.analyze_if_unknown_prototype.")

            # Generate candidates for function
            candidates, param = self.candidate_generation(db_data, error, args)

            # Dict {name of function : [list of inputs ready to give to call state]}
            candidates_inputs = self.input_generation(candidates, p, return_type)

            c_index = 0
            # Loop on candidate inputs because there can be multiple
            for c_name, c_input in candidates_inputs.items():
                try :
                    # remove number from c_name as it is only used to avoid duplicates in dict of input
                    # if a functionality has only 1 parameter there will be no _ in its name
                    if "_" in c_name:
                        c_name = c_name.split("_")[0]

                    self.logger.debug(f"Trying candidate '{c_name}'.")
                    # Expected output and prototype change 
                    expected_output = get_expected_output_db(db_data, len(c_input), param[c_index], c_name)
                    prototype = get_expected_prototype_db(db_data, len(c_input), param[c_index], c_name)
                    user_hook = get_hook(db_data, len(c_input), param[c_index], c_name)


                    # Call state generation (* to unpack a list of arguments)
                    call_state = p.factory.call_state(func.addr, *c_input, prototype=prototype, mode="tracing", add_options={angr.options.CONCRETIZE}, remove_options={angr.options.SIMPLIFY_MEMORY_WRITES, angr.options.SIMPLIFY_MEMORY_READS, angr.options.UNICORN})

                    check_func = p.factory.callable(func.addr, prototype=prototype, concrete_only=True, base_state=call_state)

                    self.logger.debug(f"Function '{func.name}', at {hex(func.addr)}: Running angr callable with concrete arguments.")
                    ret_val = check_func(*c_input)

                    self.logger.debug(f"Function '{func.name}', at {hex(func.addr)} has return value: {ret_val}")

                    comparison = self.output_comparison(expected_output, db_data[str(len(c_input))][param[c_index]][c_name]['output_type'], ret_val, c_name, func.name, func.addr, check_func.result_state)
                    
                    # If one is found, break to go to next function/ Do not search if it matches another functionality
                    if comparison:
                        self.logger_results.warning(f"CANDIDATE FUNCTIONALITY FOUND '{c_name}' for function '{func.name}', at {hex(func.addr)}!")
                        results[func.addr] = [func.name, c_name, user_hook]
                        break
                    else:
                        self.logger.warning(f"Candidate {c_name} does not work for '{func.name}' at {hex(func.addr)}, has return vale: {ret_val}")

                except UnicodeDecodeError as ex:
                    self.logger.exception(f"Could not decode the return value {ret_val} of function '{func.name}', at {hex(func.addr)}. Because of {ex}")
                except Exception as ex:
                    self.logger.exception(f"Exception: {ex}")
                c_index += 1

        return results


    def analyze_function(self, path: str, function_name: str):
        """
        Check if there is a known functionaly in our DB matching the
        analyzed function (function_name).

        Parameters
        ----------
        path : str
            Path and name of the sample
        
        function_name : str
            Name of the function to analyze

        Notes
        -----
        Useful to check only one function and not all the functions of the sample
        
        """
        with open(DB_FILE) as f:
            json_data = json.load(f)
    
        # Log with the name of the function
        self.logger.debug(f"Starting analysis of {function_name}")

        # Create CFG of program
        p = angr.Project(path, load_options={"auto_load_libs": False}, use_sim_procedures=True)
        cfg = p.analyses.CFGFast()

        # Get the prototype of the analyzed function
        analyzed_function = cfg.kb.functions[function_name]
        convention = p.analyses.CallingConvention(analyzed_function, cfg=cfg, analyze_callsites=True)

        # Check if there was an error while trying to get the calling convention
        error = False
        if convention is None:
            self.logger.error(f"Could not get calling convention of function {analyzed_function.name} at {hex(analyzed_function.addr)}")
            error = True
        if convention.prototype is None:
            self.logger.error(f"Could not get prototype of function {analyzed_function.name} at {hex(analyzed_function.addr)}")
            error = True

        args = []
        args_str = ""
        return_type = None
        if not error:
            for i, register in enumerate(convention.cc.arg_locs(convention.prototype)):
                typ = convention.prototype.args[i]
                args.append(typ.c_repr())

            return_type = convention.prototype.returnty
            self.logger.debug(f"Function {analyzed_function.name} at {hex(analyzed_function.addr)} has args {args}")
            self.logger.debug(f"Function {analyzed_function.name} at {hex(analyzed_function.addr)} has return type {return_type}")
        
        else:
            self.logger.error(f"Could not get arguments of {analyzed_function.name}.")

        if len(args) != 0:
            # Create arg strings
            args_str = ""
            # for a in args.sort():
            for a in args:
                if (args == ""):
                    args_str = a
                else:
                    args_str = args_str + ", " + a

        candidates, param = self.candidate_generation(json_data, error, args_str)

        # Dict {name of functionality : [list of inputs ready to give to call state]}
        candidates_inputs = self.input_generation(candidates, p, return_type)

        results = {}

        c_index = 0
        # Loop on candidate inputs because there can be multiple
        for c_name, c_input in candidates_inputs.items():
            try :
                # remove number from c_name as it is only used to avoid duplicates in dict of input
                # if a functionality has only 1 parameter there will be no _ in its name
                if "_" in c_name:
                    c_name = c_name.split("_")[0]

                self.logger.debug(f"Trying candidate '{c_name}'.")
                # Expected output and prototype change 
                expected_output = get_expected_output_db(json_data, len(c_input), param[c_index], c_name)
                prototype = get_expected_prototype_db(json_data, len(c_input), param[c_index], c_name)
                user_hook = get_hook(json_data, len(c_input), param[c_index], c_name)

                # Call state generation (* to unpack a list of arguments)
                call_state = p.factory.call_state(analyzed_function.addr, *c_input, prototype=prototype, mode="tracing", add_options={angr.options.CONCRETIZE}, remove_options={angr.options.SIMPLIFY_MEMORY_WRITES, angr.options.SIMPLIFY_MEMORY_READS, angr.options.UNICORN})

                check_func = p.factory.callable(analyzed_function.addr, prototype=prototype, concrete_only=True, base_state=call_state)

                self.logger.debug(f"Function '{analyzed_function.name}', at {hex(analyzed_function.addr)}: Running angr callable with concrete arguments.")
                ret_val = check_func(*c_input)

                self.logger.debug(f"Function '{analyzed_function.name}', at {hex(analyzed_function.addr)} has return value: {ret_val}")

                comparison = self.output_comparison(expected_output, json_data[str(len(c_input))][param[c_index]][c_name]['output_type'], ret_val, c_name, analyzed_function.name, analyzed_function.addr, check_func.result_state)
                
                # If one is found, break to go to next function/ Do not search if it matches another functionality
                if comparison:
                    self.logger_results.warning(f"CANDIDATE FUNCTIONALITY FOUND '{c_name}' for function '{analyzed_function.name}', at {hex(analyzed_function.addr)}!")
                    results[analyzed_function.addr] = [analyzed_function.name, c_name, user_hook]
                    break
                else:
                    self.logger.warning(f"Candidate {c_name} does not work for '{analyzed_function.name}' at {hex(analyzed_function.addr)}, has return vale: {ret_val}")

            except UnicodeDecodeError as ex:
                self.logger.exception(f"Could not decode the return value {ret_val} of function '{analyzed_function.name}', at {hex(analyzed_function.addr)}. Because of {ex}")
            except Exception as ex:
                self.logger.exception(f"Exception: {ex}")
            c_index += 1

        return results

def get_expected_output_db(db_data:dict, nb_arg:int, arg_str:str, func_name:str):
    """
    Retrieve the output of a given functionality (with args # and structure)

    Parameters
    ----------
    db_data : dict
        Dictionary of functionalities data
    nb_arg : int
        Number of arguments of functionality
    arg_str : str
        String of the types of arguments of functionality
    func_name : str
        Name of the functionality
    
    Returns
    -------
    str
        String of the output of given functionality

    """
    return db_data[str(nb_arg)][arg_str][func_name]['output']


def get_expected_prototype_db(db_data:dict, nb_arg:int, arg_str:str, func_name:str):
    """
    Retrieve the prototype of a given functionality (with args # and structure)

    Parameters
    ----------
    db_data : dict
        Dictionary of functionalities data
    nb_arg : int
        Number of arguments of functionality
    arg_str : str
        String of the types of arguments of functionality
    func_name : str
        Name of the functionality
    
    Returns
    -------
    str
        String of the prototype of given functionality

    """
    return db_data[str(nb_arg)][arg_str][func_name]['prototype']


def get_hook(db_data:dict, nb_arg:int, arg_str:str, func_name:str):
    """
    Retrieve the user hook of a given functionality (with args # and structure)

    Parameters
    ----------
    db_data : dict
        Dictionary of functionalities data
    nb_arg : int
        Number of arguments of functionality
    arg_str : str
        String of the types of arguments of functionality
    func_name : str
        Name of the functionality
    
    Returns
    -------
    str
        String of the user hook of given functionality

    """
    return db_data[str(nb_arg)][arg_str][func_name]['user_hook']


def angr_type_registration(DB_path=DB_FILE):
    """Register types for angr from DB"""

    with open(DB_path) as f:
        json_data = json.load(f)

    # Parse on all specific types and register them
    for t in json_data["types"]:
        if t.split(" ")[0] == "struct":
            angr.types.register_types(angr.types.parse_type(t))
        elif t.split(" ")[0] == "typedef":
            angr.types.register_types(angr.types.parse_types(t))
        print(f"Type registered: {t}")


def write_hooks_json(result_dict : dict, dict_file_path: os.PathLike):
    """
    Write the result to the hook dict. It will be used by SEMA toolchain to hook correct addresses

    Parameters
    ----------
    result_dict : dict
        Dictionary with the results of the functionality (key = address, value = )
    
    """
    # Keep only functionality name
    for _, v in result_dict.items():
        # Using a list eases future work for analyst
        # v1 is functionality name, v2 is hook name
        result_dict[_] = [v[1], v[2]]

    # Dump result to json
    with open(dict_file_path, 'w+') as fp:
        json.dump(result_dict, fp)


def main():
    """Create and use a FunctionIdentifyer."""

    fi = FunctionIdentifyer(sample="./samples\\gonnacry")
    #fi.analyze(full_analysis=False, function_name="generate_domain")
    #fi.analyze(True)
    #fi.analyze(full_analysis=True, func_name="dgaRamdo", arg_nb=1, arg_str="struct sSelf *")
    fi.analyze(full_analysis=True, func_name="getTrashPath", arg_nb=1, arg_str="char *")
    


if __name__ == "__main__":
    main()