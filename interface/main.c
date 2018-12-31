#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

char * get_Protocol(char * str)
{
	if (strcmp(str,"1")==0)
		return "ICMP ";
	if (strcmp(str,"6")==0)
		return "TCP ";
	if (strcmp(str,"17")==0)
		return "UDP ";
	if (strcmp(str,"255")==0)
		return "other ";
	if (strcmp(str,"143")==0)
		return "any ";
	
};

char * get_Ip(char * str)
{

	if (strcmp(str,"0.0.0.0/0")==0)
		return "any";
	return  str;
};

char * get_Direction(char * str)
{
	
	if (strcmp(str,"1")==0)
		return " in ";
	if (strcmp(str,"2")==0)
		return " out ";
	if (strcmp(str,"3")==0)
		return " any ";
};

char * get_Ack(char * str)
{
	if (strcmp(str,"1")==0)
		return "no ";
	if (strcmp(str,"2")==0)
		return "yes ";
	if (strcmp(str,"3")==0)
		return "any ";
};


char * get_Action(char * str)
{

	if (str==NULL)
		return " ";
	else if (strstr(str,"0")!=0)
		return "drop";
	else
		return "accept";
};
	
char * get_Port(char * str)
{
	printf("%s dss \n",str);
	if (strcmp(str,"0")==0)
		return "any";
	if (strcmp(str,"1023")==0)
		return ">1023";
	return str;
};	
	

int Translate_and_print(char * str)
{
	
	char rule[150]="";
	strncpy(rule,(char *)strsep(&str," "),20);	
	strncat(rule,get_Direction((char *)strsep(&str," ")),5);
	strncat(rule,get_Ip((char *)strsep(&str," ")),18);
	strncat(rule," ",3);
	strncat(rule,get_Ip((char *)strsep(&str," ")),18);
	strncat(rule," ",3);
	strncat(rule,get_Protocol((char *)strsep(&str," ")),18);
	strncat(rule,get_Port((char *)strsep(&str," ")),8);
	strncat(rule," ",3);
	strncat(rule,get_Port((char *)strsep(&str," ")),8);
	strncat(rule," ",3);
	strncat(rule,get_Ack((char *)strsep(&str," ")),9);
	strncat(rule,get_Action((char *)strsep(&str," ")),7);  
	printf("%s\n",rule);
	return 1;

};

int number_of_word_in_line(char * line)
{
    int count = 0, i;
    for (i = 0;line[i] != '\0';i++)
    {
        if (line[i] == ' ')
            count++;    
    }

   return count+1;
};

int check_name(char * name)
{
	if (strlen(name) > 20)
		return -1;
	return 1;
};

int check_direction(char * direction)
{
	if (strcmp(direction,"in")==0)
		return 1;
	if (strcmp(direction,"out")==0)
		return 1;
	if (strcmp(direction,"any")==0)
		return 1;
	return -1;
};

int check_ip_and_subent(char * str)
{
	char * ip;
	int oct1;
	int oct2;
	int oct3;
	int oct4;
	int res1;
	char temp1[20];
	strncpy(temp1,str,16);
	str=temp1;
	if (strcmp(temp1,"any")!=0)
	{
		ip=strsep(&str,"/");
		if (ip!=NULL)
		{
			oct1=atoi(strsep(&ip,"."));
			oct2=atoi(strsep(&ip,"."));
			oct3=atoi(strsep(&ip,"."));
			oct4=atoi(strsep(&ip,"."));
			if ((oct1<1) || (oct1>255))
				return -1;
			if ((oct2<0) || (oct2>255))
				return -1;
			if ((oct3<0) || (oct3>255))
				return -1;
			if ((oct4<0) || (oct4>255))
				return -1;
		};
		if (str!=NULL)
		{
			res1=atoi(str);
			if ((res1!=8) && (res1!=16)  && (res1!=24)  && (res1!=32)) 
				return -1;
		};
	}
	return 1;
};

int check_protocol(char * protocol)
{
	if (strcmp(protocol,"ICMP")==0)
		return 1;
	else if (strcmp(protocol,"TCP")==0)
		return 1;
	else if (strcmp(protocol,"UDP")==0)
		return 1;
	else if (strcmp(protocol,"any")==0)
		return 1;
	else if (strcmp(protocol,"other")==0)
		return 1;
	return -1;
};

int check_port(char * port)
{
	if (strcmp(port,"any")==0)
		return 1;
	if (strcmp(port,">1023")==0)
		return 1;
	if (atoi(port)>0 && atoi(port)<1024)
		return 1;
	return -1;
};

int check_ack(char * ack)
{	
	if (strcmp(ack,"any")==0)
		return 1;
	if (strcmp(ack,"yes")==0)
		return 1;
	if (strcmp(ack,"no")==0)
		return 1;
	return -1;
	
};

int check_policy(char * str2)
{	

	if (strstr(str2,"accept")==0)
	{
		return 1;
	}
	if (strstr(str2,"drop")==0)
	{
		return 1;
	};
	return -1;
	
};
	

int check_content_of_line(char * line)
{
	char  line_copy[100];
	char * name;
	strcpy(line_copy,line);
	char *line2=line_copy;
	if (number_of_word_in_line(line2)!=9)
		return -1;
	if (check_name(strsep(&line2," "))!=1)
		return -1;	
	if (check_direction(strsep(&line2," "))!=1)
		return -1;
	if (check_ip_and_subent(strsep(&line2," "))!=1)
		return -1; 
	if (check_ip_and_subent(strsep(&line2," "))!=1)
		return -1;  
	if (check_protocol(strsep(&line2," "))!=1)
		return -1; 
	if (check_port(strsep(&line2," "))!=1)
		return -1;
	if (check_port(strsep(&line2," "))!=1)
		return -1;
	if (check_ack(strsep(&line2," "))!=1)
		return -1;
	if (check_policy(strsep(&line2," "))!=1)
		return -1;
return 1;
};

int activate()
{
	FILE * fp1=fopen("/sys/class/fw/fw_rules/active","w");
	if (fp1==NULL)
		return -1;
	fprintf(fp1,"%u",1);
	fclose(fp1);
	return 1;
};

int deactivate()
{
	FILE * fp1=fopen("/sys/class/fw/fw_rules/active","w");
	if (fp1==NULL)
		return -1;
	fprintf(fp1,"%u",0);
	fclose(fp1);
	return 1;
};

int load_rules(char * path)
{
		char line[100];
		int is_file_valid;
		FILE * fp1=fopen("/sys/class/fw/fw_rules/rules_table","w");
		if (fp1==NULL)
			return -1;
		FILE * fp2=fopen(path,"r");
		if (fp2==NULL)
			return -2;
		while (fgets(line, 100, fp2) != NULL)
			{
				if (check_content_of_line(line)==1)
					fprintf(fp1,"%s",line);
			};
		fclose(fp2);
		fclose(fp1);
		return 1;
} 

int show_rules()
{
	char readfromsysfs[100];
	int Translated_rule;
	FILE * fp2=fopen("/sys/class/fw/fw_rules/rules_table","r");
	if (fp2==NULL)
		return -1;
	while (fgets(readfromsysfs,100,fp2)>0)
			Translated_rule=Translate_and_print(readfromsysfs);
	fclose(fp2);
};

int show_connection_table()
{
	char readfromsysfs[130];
	int Translated_rule;
	FILE * fp2=fopen("/sys/class/fw/fw/conn_tab","r");
	if (fp2==NULL)
		return -1;
	while (fgets(readfromsysfs,130,fp2)>0)
		printf("%s",readfromsysfs);
	fclose(fp2);
};	

int clear_rules()
{
	FILE * fp1=fopen("/sys/class/fw/fw_rules/rules_table","w");
	if (fp1==NULL)
		return -1;
	fprintf(fp1,"clear_rules");
	fclose(fp1);
};

int log_clear(char * str)
{
	if (strlen(str) != 1)
		return 0;
	FILE * fp1=fopen("/sys/class/fw/fw_log/log_clear","w");
	if (fp1==NULL)
		return -1;
	fprintf(fp1,"clear_log");
	fclose(fp1);
};

	
int show_log()
{
	char  len2[10];
	int length;
	FILE * fp2=fopen("/sys/class/fw/fw_log/log_size","r");
	if (fp2==NULL)
		return -1;
	fgets(len2, 12, fp2);
	fclose(fp2);
	length=atoi(len2);
	char * buff = (char*) malloc(sizeof(char)*(length*220)+1);
	if (buff==NULL)
		return -1;
	FILE * fp1=fopen("/dev/fw_log","r");  
	if (fp1==NULL)
		return -1;	
	printf("timestamp           src_ip     dst_ip src_port dst_port protocol hooknum  action reason count\n");
	fread(buff,sizeof(char),(length*220),fp1);
	//Log_transaltor(buff);
	printf("%s",buff);
	free(buff);
	fclose(fp1);
	return 50;
}


void main (int argc,char * argv[])

{	
	
	if (argc==2)
	{
		if (strcmp(argv[1],"show_rules")==0)
			show_rules();
		if (strcmp(argv[1],"activate")==0)
			activate();
		if (strcmp(argv[1],"deactivate")==0)
			deactivate();
		if (strcmp(argv[1],"clear_rules")==0)
			clear_rules();
		if (strcmp(argv[1],"show_log")==0)
			show_log();
		if (strcmp(argv[1],"show_connection_table")==0)
			show_connection_table();
		
	};
	
	if (argc==3)
	{
		if (strcmp(argv[1],"load_rules")==0)
			load_rules(argv[2]);
		if (strcmp(argv[1],"clear_log")==0)
			log_clear(argv[2]);			
	};
	


};
