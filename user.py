import os
def main():
	struct_id = int(input("Choose struct [0 - for cpu_timer, 1 - for syscall_info]: "))
	pid = int(input("Enter pid: "))
	os.system("echo '%d %d' > /proc/custom_data" % (struct_id, pid))
	os.system("cat /proc/custom_data 2>/dev/null")
if __name__ == '__main__':
	main()
