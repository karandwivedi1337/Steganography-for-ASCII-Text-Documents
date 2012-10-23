#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#define hash_size 256
#define max 2050 //max allowed size of secret message in bits=2048 bits = 256 bytes

struct Node{
char ame[64]; //american word 
char bri[64]; //british word
int col; //whether node is 0-1 (straight=0) or a 1-0 (reversed copy=1) of an existing node 1-0
struct Node* next;
};

typedef struct Node* node; //otherwise struct is necessary

//function prototypes

node search(char*);
int calchash(char buf[]);
node getnode();
void addtotable(char*, int, char*, int);
void testlist();
void createtable();
void decrypt(char*);

node hash[256]; 
char secret[max];
int secretpos=0,secretlen;

int calchash(char buf[]){
int val=0,pos=0;

while(buf[pos]!='\0'){
val+=(int)buf[pos];
pos++;
}
 return val%hash_size;
}//calchash close


node getnode(){
return (node)malloc(sizeof(struct Node));
} //getnode() close

void addtotable(char buf1[], int pos1, char buf2[], int pos2){

node wptr1=hash[pos1];

node p=getnode();

strcpy(p->ame,buf1);
strcpy(p->bri,buf2);
p->col=0;
p->next=NULL;

if(wptr1==NULL) hash[pos1]=p;

else{

node temp=hash[pos1];
while(temp->next!=NULL) temp=temp->next;

temp->next=p;
}

//do the same for the second string

node wptr2=hash[pos2];

p=getnode();

strcpy(p->ame,buf2);
strcpy(p->bri,buf1);
p->col=1;
p->next=NULL;

if(wptr2==NULL) hash[pos2]=p;

else{

node temp=hash[pos2];
while(temp->next!=NULL) temp=temp->next;

temp->next=p;
}

}//addtotable() close


void testlist(){

int i;

for(i=0;i<256;i++){

if(hash[i]!=NULL){

node p=hash[i];

while(p!=NULL){

printf("%d: %s %s %d\t",i,p->ame,p->bri,p->col);

p=p->next;
}
printf("\n");
}
}
}//testlist() close


void createtable(){
   
char buf1[64],buf2[64],c;
int i,r,pos1=0,pos2=0;

for(i=0;i<256;i++) hash[i]=NULL;

FILE* f1=fopen("table.txt","r");

c=getc(f1);

while(c!=EOF){
  
  pos1=pos2=0; //to push a new word into buf
  
  while(c!=' ' && c!='\n'&& c!= EOF){ //used to fetch a word from table file
    buf1[pos1++]=c;
    c=getc(f1);
  }
  buf1[pos1]='\0';
  
  c=getc(f1);
  
  while(c!=' ' && c!='\n' && c!= EOF){ //used to fetch a word from table file
  buf2[pos2++]=c;
  c=getc(f1);
  }
  
  buf2[pos2]='\0';
   
  int val1=calchash(buf1);
  int val2=calchash(buf2);

  addtotable(buf1,val1,buf2,val2);
  
  c=getc(f1);
  
}//read until end of table file

}//createtable() close


node search(char buf[]){
 
 int index=calchash(buf); //index in hash table for the current word
    
 node temp=hash[index];
  
 if(temp==NULL) return NULL; 
 
 while(temp!=NULL){
	 
	 if(strcasecmp(temp->ame,buf)==0) return temp;
	 else temp=temp->next;
 }
 
 return temp; 
}//search() close


void extract(){
	
	char c,buf[64],pos=0;
	int match=0;
	
	FILE* f1=fopen("cover.txt","r"); //initial cover text

    c=getc(f1);
     
    while(c!=EOF){
    
        pos=0;
    
		while((c==' ' || c=='\n' ||  c=='\t') && c!= EOF) c=getc(f1);

		while(c!=' ' && c!='\n' &&  c!='\t' && c!= EOF){ //used to fetch a word from basecover.txt
		//if(buf[pos]!=',' || buf[pos]!='.')
		buf[pos++]=c;
    
		c=getc(f1);
		}
  
      buf[pos]='\0';
 
    node pairword=search(buf); //pairword is null if word is not found in the list
                              // else pairword contains the word to substitute in place of buf in cover.txt

    if(pairword!=NULL){
		match++;
	    secret[secretpos++]=pairword->col+48;
    }

}//while(c!=EOF) close

   secret[secretpos]='\0';
    secretlen=secretpos;	
	fclose(f1);
	
}//extract() close

void decrypt(char* pass){
	
	FILE *f1=fopen("decryptme.txt","w");
	
	int i,k,n,val=0,endmarker=0; //endmarker is used to search for the delimiter %%
	char temp;
	
	for(i=0;i<secretlen;i+=8){  //secretlen-16 will discard %% appended at the end of secret[] as binary bits
		                           //check presence of %% if length of secret message is not pre-defined!
		val=0;
		
		for(k=0;k<8;k++){
			n=(int)secret[i+7-k]-48;
               	val+=n*pow(2.0,(double)k);
		}
		
		if((char)val=='%'){
			 ++endmarker;
			 temp=(char)val;
		i+=8;
		
		val=0;
		
		for(k=0;k<8;k++){
			n=(int)secret[i+7-k]-48;
               	val+=n*pow(2.0,(double)k);
		}
		
		if((char)val=='%') ++endmarker;
	}//if val=='%' close
		
		if(endmarker==2) break;
		
		else if(endmarker==1){
			putc(temp,f1);
			//printf("%c",temp);
			
			putc((char)val,f1);
			//printf("%c",(char)val);
			endmarker=0;
		    continue;
		}
		
	    putc((char)val,f1);
	    //printf("%c",(char)val);
	}
	
	fclose(f1);
	
	char initcomm[]="openssl enc -d -aes-256-cbc -a -in decryptme.txt -out decrypted.txt.gz -pass pass:";
	char command[1024];
	
	memset(command,'\0',1024); //prevent garbage during string handling
	
	strcat(command,initcomm);
	strcat(command,pass);
     
    int ret=system(command);
	
	if (ret!=0)
	printf("%d","Error while decrypting the message. Exiting \n");	
		
}//decrypt() close


void decompress(){

int ret;
    	
	ret=system("gunzip -c decrypted.txt.gz > message.txt");
	
	if (ret!=0)
	printf("%c","Error while decompressing the message. Exiting \n");
	
}

int main(int argc, char* argv[]){

if(argc!=2){
printf("%s","Usage: <executable name> <password> \n");
exit(1);
}

createtable();

extract(); //extracts secret data (in binary) to secret[]

decrypt(argv[1]); //decompresses and decrypts the received stego object

decompress();

printf("Secret message written to message.txt\n");

return 0;
}