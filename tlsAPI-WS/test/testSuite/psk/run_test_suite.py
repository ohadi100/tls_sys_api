#!/usr/bin/python
import subprocess
import time
import datetime
import os
import sys
import random
import string
import getopt
import glob

FILE_PATH = os.path.dirname(os.path.abspath(__file__))
BIN_PATH = FILE_PATH + '/../../../build/bin/'

INI_PATH =  FILE_PATH + '/server_client_input.ini'
LOG_PATH =  FILE_PATH + '/log.txt'
HANDSHAKE_PATH =  FILE_PATH + '/handshake_result.txt'

DEV_MODE = False # development mode
SUPPORT_LOG = True
MAX_MESSAGES = 10
MAX_MESSAGE_LEN = 1022 # + 1 (c for client / s for server) + null terminator

tests_suite_combination_test = {
	'Server (Authentic & Confidential) | Client (Authentic)':
		{
			'arrayOfClients':
				[
					{
						'securityLevel':'0',
						'port':'1341',
						'msg':'client1',
						'num_of_send/rcv':'2',
					},
				],
			'arrayOfServers':
				[
					{
						'securityLevel':'0',
						'port':'1341',
						'msg':'server1_a',
						'num_of_send/rcv':'3',
					},
					{
						'securityLevel':'1',
						'port':'1343',
						'msg':'server1_b',
						'num_of_send/rcv':'3',
					}
				]
		},
	'Server (Authentic & Confidential) | Client (Confidential)':
		{
			'arrayOfClients':
				[
					{
						'securityLevel':'1',
						'port':'1343',
						'msg':'client1',
						'num_of_send/rcv':'1',
					},
				],
			'arrayOfServers':
				[
					{
						'securityLevel':'0',
						'port':'1341',
						'msg':'server1_a',
						'num_of_send/rcv':'8',
					},
					{
						'securityLevel':'1',
						'port':'1343',
						'msg':'server1_b',
						'num_of_send/rcv':'8',
					}
				]
		},
	'Server (Authentic & Confidential) | Client (Authentic & Confidential)':
		{
			'arrayOfClients':
				[
					{
						'securityLevel':'0',
						'port':'1341',
						'msg':'client1_a',
						'num_of_send/rcv':'8',
					},
					{
						'securityLevel':'1',
						'port':'1343',
						'msg':'client1_b',
						'num_of_send/rcv':'5',
					},
				],
			'arrayOfServers':
				[
					{
						'securityLevel':'0',
						'port':'1341',
						'msg':'server1_a',
						'num_of_send/rcv':'8',
					},
					{
						'securityLevel':'1',
						'port':'1343',
						'msg':'server1_b',
						'num_of_send/rcv':'8',
					}
				]
		},
	'Server (Authentic) | Client (Authentic & Confidential)':
		{
			'arrayOfClients':
				[
					{
						'securityLevel':'0',
						'port':'1341',
						'msg':'client1_a',
						'num_of_send/rcv':'8',
					},
					{
						'securityLevel':'1',
						'port':'1343',
						'msg':'client1_b',
						'num_of_send/rcv':'5',
					},
				],
			'arrayOfServers':
				[
					{
						'securityLevel':'0',
						'port':'1341',
						'msg':'server1',
						'num_of_send/rcv':'8',
					}
				]
		},
	'Server (Confidential) | Client (Authentic & Confidential)':
		{
			'arrayOfClients':
				[
					{
						'securityLevel':'0',
						'port':'1341',
						'msg':'client1_a',
						'num_of_send/rcv':'8',
					},
					{
						'securityLevel':'1',
						'port':'1343',
						'msg':'client1_b',
						'num_of_send/rcv':'5',
					},
				],
			'arrayOfServers':
				[
					{
						'securityLevel':'1',
						'port':'1343',
						'msg':'server1',
						'num_of_send/rcv':'8',
					}
				]
		},
}


tests_suite_multi_client_test = {
	'arrayOfServers':
		[
			{
				'securityLevel':'0',
				'port':'1341',
				'msg':'server1_a',
				'num_of_send/rcv':'20',
			},
			{
				'securityLevel':'0',
				'port':'1342',
				'msg':'server1_b',
				'num_of_send/rcv':'20',
			},
			{
				'securityLevel':'1',
				'port':'1343',
				'msg':'server1_c',
				'num_of_send/rcv':'20',
			},
			{
				'securityLevel':'1',
				'port':'1344',
				'msg':'server1_d',
				'num_of_send/rcv':'20',
			},
		],
	'arrayOfInstanceClients':
		[
			{
				'arrayOfClients':
					[
						{
							'securityLevel':'0',
							'port':'1341',
							'msg':'client1_a',
							'num_of_send/rcv':'20',
						},
						{
							'securityLevel':'0',
							'port':'1342',
							'msg':'client1_b',
							'num_of_send/rcv':'20',
						},
						{
							'securityLevel':'1',
							'port':'1343',
							'msg':'client1_c',
							'num_of_send/rcv':'20',
						},
						{
							'securityLevel':'1',
							'port':'1344',
							'msg':'client1_d',
							'num_of_send/rcv':'20',
						},
					]
			},
			{
				'arrayOfClients':
					[
						{
							'securityLevel':'0',
							'port':'1341',
							'msg':'client2_a',
							'num_of_send/rcv':'20',
						},
						{
							'securityLevel':'0',
							'port':'1342',
							'msg':'client2_b',
							'num_of_send/rcv':'20',
						},
						{
							'securityLevel':'1',
							'port':'1343',
							'msg':'client2_c',
							'num_of_send/rcv':'20',
						},
						{
							'securityLevel':'1',
							'port':'1344',
							'msg':'client2_d',
							'num_of_send/rcv':'20',
						},
					]
			},
			{
				'arrayOfClients':
					[
						{
							'securityLevel':'0',
							'port':'1341',
							'msg':'client3_a',
							'num_of_send/rcv':'20',
						},
						{
							'securityLevel':'0',
							'port':'1342',
							'msg':'client3_b',
							'num_of_send/rcv':'20',
						},
						{
							'securityLevel':'1',
							'port':'1343',
							'msg':'client3_c',
							'num_of_send/rcv':'20',
						},
						{
							'securityLevel':'1',
							'port':'1344',
							'msg':'client3_d',
							'num_of_send/rcv':'20',
						},
					]
			},
		],
}

class bcolors:
	CYAN  = '\033[44m'
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	STATUSYELLOW = '\033[93m'
	RED = '\033[41m'
	FAIL = '\033[91m'
	CREDBG    = '\033[41m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	CBEIGE  = '\033[36m'
	GREEN = '\033[42m'
	BROWN = '\033[33m'
	COLOR_BLACK="\033[0;30m"
	ITALIC = "\033[3m"
	LIGHT_GRAY = "\033[0;37m"
	DARK_GRAY = "\033[1;30m"
	BLINK = "\033[5m"
	CROSSED = "\033[9m"


def print_with_color(message, color):
	if SUPPORT_LOG:
		with open (LOG_PATH, 'a') as log_file:
			log_file.write(message + "\n")
	print (color + message + bcolors.ENDC)


def LOG_DEV(msg):
	if DEV_MODE:
		print_with_color(str(msg), bcolors.LIGHT_GRAY)


def removeAllFiles():
	#remove files
	for file in glob.glob("*clientOutput.txt"):
		os.remove(file)

	for file in glob.glob("*serverOutput.txt"):
		os.remove(file)


#waits until all processes in processes array will terminate
def waitAllProcesses(processes_array):
	for process in processes_array:
		process.wait()

#kills all processes in processes array
def killAllProcesses(processes_array):
	for process in processes_array:
		process.kill()


def check_complex_test(values):
	is_passed = True
	index = 1
	for instanceClient in values.get('arrayOfInstanceClients'):
		with open(str(index) + 'clientOutput' + '.txt', 'r') as output_of_client_file:
			output_of_client_file.flush()
			output_of_client = output_of_client_file.read()

		clients = instanceClient.get('arrayOfClients')
		servers = values.get('arrayOfServers')
		check_handshake_time(output_of_client)
		is_passed = is_passed and check_results_by_client(clients, servers, output_of_client)
		index = index + 1

	return is_passed


def check_simple_test(values):
	with open('clientOutput.txt', 'r') as output_of_client_file:
		output_of_client_file.flush()
		output_of_client = output_of_client_file.read()

	clients = values.get('arrayOfClients')
	servers = values.get('arrayOfServers')

	return check_results_by_client(clients, servers, output_of_client)


def search_line_in_string(string, start_with_word):

	results = ""
	lines = string.split("\n")
	for line in lines:
		if line.startswith(start_with_word):
			results += line.split()[1]
			results += '\n'
	return results


def check_results_by_client(clients, servers, output_of_client):
	is_passed = True

	for client in clients:
		for server in servers:
			if server.get('port') == client.get('port') and server.get('securityLevel') == client.get('securityLevel'):
				num_of_exchange_msg = int(client.get('num_of_send/rcv'))

				str_messages1 = "CLIENT send successfully: " + str(client.get('msg'))
				str_messages2 = "CLIENT read successfully: " + str(server.get('msg'))

				count_messages1 = output_of_client.count(str_messages1)
				count_messages2 = output_of_client.count(str_messages2)

				is_passed_tmp1 = (count_messages1 == num_of_exchange_msg)
				is_passed_tmp2 = (count_messages2 == num_of_exchange_msg)

				if is_passed_tmp1 and is_passed_tmp2:
					continue
				else:
					is_passed = is_passed and is_passed_tmp1 and is_passed_tmp2
					if not is_passed_tmp1:
						print_with_color('Expected num messages: ' + str(num_of_exchange_msg) + ', but found ' + str(count_messages1), bcolors.FAIL)
					if not is_passed_tmp2:
						print_with_color('Expected num messages: ' + str(num_of_exchange_msg) + ', but found ' + str(count_messages2), bcolors.FAIL)

	if not is_passed:
		with open(LOG_PATH, 'a') as log_file:
			log_file.write(output_of_client + '\n\n')
	elif is_passed:
		check_handshake_time(output_of_client)

	return is_passed


def check_handshake_time(output_of_client):
	with open (HANDSHAKE_PATH, 'a') as handshake_result_file:
		message = search_line_in_string(output_of_client, "Elapsed");
		handshake_result_file.write(str(message))
		handshake_result_file.flush()


def random_string():
	string_length = int(random.randrange(1, MAX_MESSAGE_LEN, 1))
	return ''.join(random.choice(string.ascii_letters) for i in range(string_length))


def run_proc_test_suite_cli(values):
	input_to_cli_for_servers = [values.get('ipServer'), values.get('domainNameServer')]
	input_to_cli_for_clients = [values.get('ipClient'), values.get('domainNameClient')]

	clients = values.get('arrayOfClients')
	servers = values.get('arrayOfServers')

	for client in clients:
		# random num of msg to send/rcv
		client['num_of_send/rcv'] = str(int(random.randrange(1, MAX_MESSAGES, 1)))

		if 'botan' in EXE_ENGINE_PATH:
			client['securityLevel'] = '1'

		# random msg size and letters
		client['msg'] = "c" + random_string()

		input_to_cli_for_clients += ['c', client.get('securityLevel'), client.get('port'), client.get('msg'), client.get('num_of_send/rcv')]

	for server in servers:
		# random msg size and letters
		server['msg'] = "s" + random_string()

		if 'botan' in EXE_ENGINE_PATH:
			server['securityLevel'] = '1'

		input_to_cli_for_servers += ['s', server.get('securityLevel'), server.get('port'), server.get('msg'), server.get('num_of_send/rcv')]

	cmd_test_suite_cli = [EXE_PATH_CLI]

	LOG_DEV(cmd_test_suite_cli + input_to_cli_for_servers)
	LOG_DEV(cmd_test_suite_cli + input_to_cli_for_clients)

	with open ('serverOutput.txt', 'wb') as out_server:
		proc_test_suite_cli_servers = subprocess.Popen(cmd_test_suite_cli + input_to_cli_for_servers, stdout=out_server, stderr=out_server, stdin=subprocess.PIPE)
	time.sleep(1)

	with open ('clientOutput.txt', 'wb') as out_client:
		proc_test_suite_cli_clients = subprocess.Popen(cmd_test_suite_cli + input_to_cli_for_clients, stdout=out_client, stderr=out_client, stdin=subprocess.PIPE)
	time.sleep(1)

	#wait until clients will terminated
	proc_test_suite_cli_clients.wait()
	proc_test_suite_cli_servers.kill()
	#wait_client_thread_completed('clientOutput.txt')


def run_test_helper(key, values):
	print_with_color('run test: ' + key, bcolors.CYAN)

	#start the process.
	try:
		run_proc_test_suite_cli(values)
		#check if the test passed - return true/false according to succeess
		is_passed = check_simple_test(values)
	finally:
		pass

	return is_passed


def run_multi_client_test_helper():
	print_with_color('run test: Multiple Clients', bcolors.CYAN)
	input_to_cli_for_servers = [tests_suite_multi_client_test.get('ipServer'), tests_suite_multi_client_test.get('domainNameServer')]

	cmd_test_suite_cli = [EXE_PATH_CLI]

	#load the servers
	servers = tests_suite_multi_client_test.get('arrayOfServers')

	arrayServerInstancesProcesses = []
	for server in servers:
		server['msg'] = 's' + random_string()
		if 'botan' in EXE_ENGINE_PATH:
			server['securityLevel'] = '1'
		serverArray = ['s', server.get('securityLevel'), server.get('port'), server.get('msg'), server.get('num_of_send/rcv')]
		input_to_cli_for_servers += serverArray

	with open ("serverOutput.txt","wb") as out_server:
		input_cli = cmd_test_suite_cli + input_to_cli_for_servers
		LOG_DEV(input_cli)

		proc_test_suite_cli_servers = subprocess.Popen(input_cli, stdout=out_server, stderr=out_server, stdin=subprocess.PIPE)
		arrayServerInstancesProcesses.append(proc_test_suite_cli_servers)
	time.sleep(1)

	#load the client instances
	numInstanceClient = 0
	arrayClientInstancesProcesses = []
	for instanceClient in tests_suite_multi_client_test.get('arrayOfInstanceClients'):
		numInstanceClient += 1
		input_to_cli_for_clients = [instanceClient.get('ipClient'), instanceClient.get('domainNameClient')]

		for client in instanceClient.get('arrayOfClients'):
			client['msg'] = 'c' + random_string()
			if 'botan' in EXE_ENGINE_PATH:
				client['securityLevel'] = '1'
			clientArray = ['c', client.get('securityLevel'), client.get('port'), client.get('msg'), client.get('num_of_send/rcv')]
			input_to_cli_for_clients += clientArray

		fileClientInstanceName = str(numInstanceClient) + "clientOutput" + ".txt"
		with open (fileClientInstanceName ,"wb") as out_client:
			input_cli = cmd_test_suite_cli + input_to_cli_for_clients
			LOG_DEV(input_cli)

			proc_test_suite_cli_clients = subprocess.Popen(input_cli, stdout=out_client, stderr=out_client, stdin=subprocess.PIPE)
			arrayClientInstancesProcesses.append(proc_test_suite_cli_clients)

	#waits until clients will terminated
	waitAllProcesses(arrayClientInstancesProcesses)

	#kills servers processes
	killAllProcesses(arrayServerInstancesProcesses)

	#check if the test succeed
	is_passed = check_complex_test(tests_suite_multi_client_test)

	return is_passed


def run_tests(passed, count, selected_test="all"):
	# tests_suite_combination_test
	for key, values in tests_suite_combination_test.items():
		if key != selected_test and selected_test != "all":
			continue
		count +=1
		if run_test_helper(key, values):
			print_with_color( "Passed successfully." , bcolors.GREEN)
			passed += 1
		else:
			print_with_color("test " + key + " have failed", bcolors.FAIL)
			#stop after the first failure in development mode
			if DEV_MODE:
				return passed, count

		print_with_color('\n==============================================================\n', bcolors.HEADER)

	# run_multi_client
	if selected_test == "tests_suite_multi_client_test" or selected_test == "all":
		count +=1
		if run_multi_client_test_helper():
			print_with_color("Passed successfully." , bcolors.GREEN)
			passed += 1
		else:
			print_with_color("test multi client have failed"  , bcolors.FAIL)
			#stop after the first failure in development mode
			if DEV_MODE:
				return passed, count
		print_with_color('\n==============================================================\n', bcolors.HEADER)

	#removes all processes files if not in development mode
	if not DEV_MODE:
		removeAllFiles()

	return passed, count

def read_ini_file():
	client_instances_input = []
	server_input = []
	if not os.path.exists(INI_PATH):
		return False
	with open (INI_PATH, 'r') as input_for_tests_file:
		for line in input_for_tests_file:
			list_input = line.split()
			if list_input[0] == 'server:':
				ip_server = list_input[1]
				domain_server = list_input[2]
				server_input.append(ip_server)
				server_input.append(domain_server)
			if list_input[0] == 'client:':
				ip_client = list_input[1]
				domain_client = list_input[2]
				client_instances_input.append([ip_client, domain_client])

	#update values in dictionary
	for key, values in tests_suite_combination_test.items():
		values['ipServer'] = server_input[0]
		values['domainNameServer'] = server_input[1]
		values['ipClient'] = client_instances_input[0][0]
		values['domainNameClient'] = client_instances_input[0][1]

	tests_suite_multi_client_test['ipServer'] = server_input[0]
	tests_suite_multi_client_test['domainNameServer'] = server_input[1]

	num_instance_client = 0
	for instanceClient in tests_suite_multi_client_test.get('arrayOfInstanceClients'):
		instanceClient['ipClient'] = client_instances_input[num_instance_client][0]
		instanceClient['domainNameClient'] = client_instances_input[num_instance_client][1]
		num_instance_client += 1
	return True

def print_tests_results(passed, count, handshake_time, start):
	summ = '--------------------------\n' \
		   '' +str(passed)+ '/' + str(count)+ ' tests passed. ' \
											  '(' + str(100 * float(passed)/float(count)) + '%)\n' \
																							'--------------------------'

	print_with_color(summ, bcolors.OKBLUE)
	end = datetime.datetime.now()

	print_with_color('--------------------------', bcolors.STATUSYELLOW)
	print_with_color('average handshake time: ' + str(handshake_time) + ' microseconds', bcolors.STATUSYELLOW)
	print_with_color('elapsed time: ' + str(end - start), bcolors.STATUSYELLOW)
	print_with_color('--------------------------', bcolors.STATUSYELLOW)

def calculate_avg_handshake_time(path):
	numbers = []

	with open(path, 'r') as fp:
		for line in fp:
			try:
				numbers.append(int(line))
			except ValueError:
				continue

	if len(numbers) > 0:
		return sum(numbers)/(len(numbers))
	return -1

def print_options_description():
	print_with_color("Add option -e or --engine : 'b' for botan engine or 'w' for wolfssl engine.",
							bcolors.OKBLUE)
	print_with_color("The default is running once - you can change it by adding option -t or --times : and number.",
							bcolors.OKBLUE)
	print_with_color("The default is to run all servers tests - you can change it by adding option -s or --server : and server valid name.",
							bcolors.OKBLUE)

def main():

	passed = 0
	count = 0
	times = 1
	selected_test = "all"
	argv = sys.argv[1:]# Get the arguments from the command-line except the filename
	global EXE_ENGINE_PATH
	global EXE_PATH_CLI

	if SUPPORT_LOG:
		with open(LOG_PATH, 'w') as log_file:
			log_file.write('LOG:\n')
		open(HANDSHAKE_PATH, 'w')

	try:
		# Define the getopt parameters
		opts, args = getopt.getopt(argv, 'e:t:f:d', ['engine=', 'times=', 'filter='] )
		dic_opts = dict(opts)
		if (not dic_opts.has_key('-e') and not dic_opts.has_key('--engine')) or len(opts) == 0 or len(opts) > 4 :
			print_options_description()
			return
		else:
			# Iterate the options and get the corresponding values
			for opt, arg in opts:
				if opt in ('-e', '--engine'):
					if arg == 'b':
						EXE_ENGINE_PATH = 'botan_psk_test_suite'
					elif arg == 'w':
						EXE_ENGINE_PATH = 'wolfssl_psk_test_suite'
				elif opt in ('-t', '--times'):
					times = int(arg)
				elif opt in ('-f', '--filter'):
					selected_test = arg
				elif opt in ('-d'):
					global DEV_MODE
					DEV_MODE = True


	except getopt.GetoptError:
		print_options_description()
		sys.exit(2)

	EXE_PATH_CLI = BIN_PATH + EXE_ENGINE_PATH

	if not read_ini_file():
		print_with_color(INI_PATH + ' file is missing or invalid.', bcolors.FAIL)
		exit(1)

	t_end = time.time() + 60 * times
	start = datetime.datetime.now()

	while time.time() < t_end:
		try:
			passed, count = run_tests(passed, count, selected_test)
			#break if any test fails, if in development mode
			if DEV_MODE and passed != count:
				break

		finally:
			#kill the process
			os.system("killall " + EXE_ENGINE_PATH)

	print_tests_results(passed, count, str(calculate_avg_handshake_time(HANDSHAKE_PATH)), start)

if __name__ == "__main__":
	main()