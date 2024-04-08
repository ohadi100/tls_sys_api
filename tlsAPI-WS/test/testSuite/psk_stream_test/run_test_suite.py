#!/usr/bin/python
import subprocess
import time
import datetime
import os
import sys
import random
import string
import getopt

FILE_PATH = os.path.dirname(os.path.abspath(__file__))
BIN_PATH = FILE_PATH + '/../../../build/bin/'
INI_PATH =  FILE_PATH + '/server_client_input.ini'

LOG_PATH =  FILE_PATH + '/log.txt'

DEV_MODE = False # development mode
SUPPORT_LOG = True
MAX_MESSAGES = 5
MAX_MESSAGE_LEN = 1022 # + 1 (c for client / s for server) + null terminator

tests_suite_combination_test = {
	'1 Server | 1 Client':
		{
			'arrayOfClients':
				[
					{
						'securityLevel':'0',
						'port':'1341',
						'msg':'client1_a',
						'num_of_send/rcv':'8',
					}
				],
			'arrayOfServers':
				[
					{
						'securityLevel':'0',
						'port':'1341',
						'msg':'server1_a',
						'num_of_send/rcv':'8',
					}
				]
		},
	'2 Servers | 2 Clients':
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
		}
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


def	wait_client_thread_completed(path, num_of_connected_client):
	loops = 10
	is_passed = False
	output_of_client = ''

	while loops > 0:
		with open(path, 'r') as x:
			output_of_client = x.read()
		if "Done!" in str(output_of_client):
			is_passed = True
			break
		time.sleep(1.0)
		loops -= 1

	if is_passed:
		count_messages = output_of_client.count("successfully connected to server")
		if count_messages != num_of_connected_client:
			is_passed = False
			print_with_color("connection failed", bcolors.FAIL)
	else:
		print_with_color("multi-thread failed", bcolors.FAIL)

	if not is_passed:
		with open(LOG_PATH, 'a') as log_file:
			log_file.write('\nclient output fail:\n')
			log_file.write(output_of_client)

	return is_passed


def search_line_in_string(string, start_with_word):

	results = ""
	lines = string.split("\n")
	for line in lines:
		if line.startswith(start_with_word):
			results += line.split()[1]
			results += '\n'
	return results

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

		if 'botan' in EXE_PATH_CLI:
			client['securityLevel'] = '1'

		# random msg size and letters
		client['msg'] = "c" + random_string()

		input_to_cli_for_clients += ['c', client.get('securityLevel'), client.get('port'), client.get('msg'), client.get('num_of_send/rcv')]

	for server in servers:
		# random msg size and letters
		server['msg'] = "s" + random_string()

		if 'botan' in EXE_PATH_CLI:
			server['securityLevel'] = '1'

		input_to_cli_for_servers += ['s', server.get('securityLevel'), server.get('port'), server.get('msg'), server.get('num_of_send/rcv')]

	cmd_test_suite_cli = [EXE_PATH_CLI]

	with open ('serverOutput.txt', 'wb') as out_server:
		proc_test_suite_cli_servers = subprocess.Popen(cmd_test_suite_cli + input_to_cli_for_servers, stdout=out_server, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	time.sleep(1)

	with open ('clientOutput.txt', 'wb') as out_client:
		proc_test_suite_cli_clients = subprocess.Popen(cmd_test_suite_cli + input_to_cli_for_clients, stdout=out_client, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	time.sleep(1)

	#wait until clients will terminated
	is_passed = wait_client_thread_completed('clientOutput.txt', min(len(client), len(servers)))

	#removes files if not in development mode
	if not DEV_MODE:
		os.remove('clientOutput.txt')
		os.remove('serverOutput.txt')

	proc_test_suite_cli_servers.kill()

	return is_passed


def run_test_helper(key, values):
	print_with_color('run test: ' + key, bcolors.CYAN)
	#start the process.
	is_passed = run_proc_test_suite_cli(values)

	return is_passed


def run_tests(passed, count):
	# tests_suite_combination_test
	for key, values in tests_suite_combination_test.items():
		count +=1
		if run_test_helper(key, values) == True:
			print_with_color( "Passed successfully." , bcolors.GREEN)
			passed += 1
		else:
			print_with_color("test " + key + " have failed", bcolors.FAIL)
			#stop after the first failure in develop mode
			if DEV_MODE:
				return passed, count
		print_with_color('\n==============================================================\n', bcolors.HEADER)

	return passed, count


def read_ini_file():
	client_instances_input = []
	server_input = []
	if not os.path.exists(INI_PATH):
		return False
	with open (INI_PATH, 'r') as input_for_tests_file:
		for line in input_for_tests_file:
			list_input = line.split()
			if (list_input[0] == 'server:'):
				ip_server = list_input[1]
				domain_server = list_input[2]
				server_input.append(ip_server)
				server_input.append(domain_server)
			if (list_input[0] == 'client:'):
				ip_client = list_input[1]
				domain_client = list_input[2]
				client_instances_input.append([ip_client, domain_client])

	#update values in dictionary
	for key, values in tests_suite_combination_test.items():
		values['ipServer'] = server_input[0]
		values['domainNameServer'] = server_input[1]
		values['ipClient'] = client_instances_input[0][0]
		values['domainNameClient'] = client_instances_input[0][1]

	return True


def print_tests_results(passed, count, start):
	summ = '--------------------------\n' \
		   '' +str(passed)+ '/' + str(count)+ ' tests passed. ' \
											  '(' + str(100 * float(passed)/float(count)) + '%)\n' \
																							'--------------------------'

	print_with_color(summ, bcolors.OKBLUE)
	end = datetime.datetime.now()

	print_with_color('--------------------------', bcolors.STATUSYELLOW)
	print_with_color('elapsed time: ' + str(end - start), bcolors.STATUSYELLOW)
	print_with_color('--------------------------', bcolors.STATUSYELLOW)

def print_options_description():
	print_with_color("Add option -e or --engine : 'b' for botan engine or 'w' for wolfssl engine.",
							bcolors.OKBLUE)
	print_with_color("The default is running once - you can change it by adding option -t or --times : and number.",
							bcolors.OKBLUE)

def main():

	passed = 0
	count = 0
	minutes = 5
	global EXE_ENGINE_PATH
	global EXE_PATH_CLI

	if SUPPORT_LOG:
		with open(LOG_PATH, 'w') as log_file:
			log_file.write('LOG:\n')

	try:
		argv = sys.argv[1:]# Get the arguments from the command-line except the filename
		# Define the getopt parameters
		opts, args = getopt.getopt(argv, 'e:t:f:d', ['engine=', 'times=', 'filter=',] )
		dicOpts = dict(opts)
		if (not dicOpts.has_key('-e') and not dicOpts.has_key('--engine')) or len(opts) == 0 or len(opts) > 4 :
			print_options_description()
			return
		else:
			# Iterate the options and get the corresponding values
			for opt, arg in opts:
				if opt in ('-e', '--engine'):
					if arg == 'b':
						EXE_ENGINE_PATH = 'botan_psk_stream_test_suite'
					elif arg == 'w':
						EXE_ENGINE_PATH = 'wolfssl_psk_stream_test_suite'
				elif opt in ('-t', '--times'):
					minutes = int(arg)
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

	t_end = time.time() + 60 * minutes
	start = datetime.datetime.now()

	while time.time() < t_end:
		try:
			passed, count = run_tests(passed, count)
			#break if any test fails, if in development mode
			if DEV_MODE and passed != count:
				break
		finally:
			#kill the process
			os.system("killall " + EXE_ENGINE_PATH)

	print_tests_results(passed, count, start)

if __name__ == "__main__":
	main()