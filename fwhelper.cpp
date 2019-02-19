//Author: Garrett Lee
#include <iostream>
#include <fstream>
#include <cstdio>
#include "fwhelper.hpp"


int optionSelect() {
	int option = 0;
	std::cout << "The options available are:" << std::endl;
	std::cout << "1. Add a rule \n2. Delete a rule\n\nTo exit enter 0" << std::endl;
	std::cout << "Please input a function number: ";
	while (std::cin >> option && option != 0) {
		switch (option) {
			case 1:
				std::cout << std::endl;
				return addRule();
			case 2:
				std::cout << std::endl;
				return deleteRule();
			default:
				std::cout << "That is an invalid argument please try again." << std::endl;
				continue;
		}
	}
	return 0;

}

int addRule() {
	std::fstream outfile;
	outfile.open("config.dat", std::ios::out | std::ios::app); //Open config file
	std::fstream procfs;
	procfs.open("/proc/lkmfirewall", std::ios::out | std::ios::app); //Opens proc file

	if (outfile && procfs) {

		std::string s;
		std::cout << "Please input your rule in this format:\nSourceIP Port" << std::endl; //Need to determine format
		std::cin.ignore();
		std::getline(std::cin, s);
		outfile << s << std::endl;
		procfs << s << std::endl;

		outfile.close();
		procfs.close();

	}
	
	else {
		std::cerr << "Error opening config.dat or error with /proc/lkmfirewall" << std::endl;
		exit(-1);
	}

	std::cout << "Would you like to make additional changes? Y/n ";
	std::string response;
	return (std::cin >> response && (response == "Y" || response == "y"));
}

int deleteRule() {
	std::fstream file;
	file.open("config.dat", std::ios::in | std::ios::out);
	std::fstream tmp;
	tmp.open("tmp.dat", std::ios::out);

	if (file && tmp) {

		std::string s;
		std::cout << "Please input the IP of the rule you want to be deleted" << std::endl;
		std::cin.ignore();
		std::getline(std::cin, s);

		char data[100];
		while(file.getline(data,100)) {
			for (int i = 0; i < s.length(); ++i) {
				if (s[i] != data[i]) {
					tmp << data << std::endl;
					break;
				}
			}
		}

		file.close();
		tmp.close();

		std::remove("config.dat");
		std::rename("tmp.dat", "config.dat");
	}	
		
	else {
		std::cerr << "Error opening config.dat or opening tmp.data" << std::endl;
		exit(-1);
	}

	std::cout << "Would you like to make additional changes? Y/n ";
	std::string response;
	return (std::cin >> response && (response == "Y" || response == "y"));
}

int main() {
	std::cout << "Welcome to the lkmfirewall companion tool." << std::endl;
	std::cout << "From here you can configure the rules for the lkmfirewall." << std::endl;
	std::cout << "Configurations can also be written directly in the config file." << std::endl;
	std::cout << "------------------------------" <<std::endl;
	while (1) {
		if (!optionSelect()) {
			break;
		}
	}

	std::cout << "\nYour changes have been committed." << std::endl;
	return 0;
}
