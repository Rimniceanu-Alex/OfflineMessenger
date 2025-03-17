#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <utmp.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#define PORT 2500
#define TRUE 1
#define FALSE 0

char current_file_we_in[1024];

struct account
{
    char username[100];
    char password[100];
};

int count_chat_lines(FILE *chat_descriptor)
{
    int count = 0;
    char line_of_chat[1024];
    while (fgets(line_of_chat, sizeof(line_of_chat), chat_descriptor))
    {
        count++;
    }
    fseek(chat_descriptor, 0, SEEK_SET);
    return count;
}

int validate(char usr[100], char pass[100])
{
    FILE *fd;
    if ((fd = fopen("./user_validation.txt", "r")) == NULL)
    {
        perror("[Server][validate()]Error opening user_validation for reading.\n");
        return errno;
    }
    FILE *logged_already;
    if ((logged_already = fopen("./logged_users.txt", "r")) == NULL)
    {
        perror("[Server][validate()]Error opening the logged_users for reading.\n");
        fclose(fd);
        return errno;
    }
    char check_line[1024];
    while (fgets(check_line, sizeof(check_line), logged_already))
    {
        check_line[strlen(check_line) - 1] = '\0';
        if (strcmp(usr, check_line) == 0)
        {
            fclose(fd);
            fclose(logged_already);
            return 2;
        }
    }
    fclose(logged_already);
    char line[1024];
    while (fgets(line, sizeof(line), fd))
    {
        char *tokken;
        tokken = strtok(line, " ");
        if (strcmp(tokken, usr) == 0)
        {
            tokken = strtok(NULL, " ");
            tokken[strlen(tokken) - 1] = '\0';
            if (strcmp(tokken, pass) == 0)
            {
                fclose(fd);
                return TRUE;
            }
        }
    }
    fclose(fd);
    return FALSE;
}

void sending_chat_content(int clients_filedescriptor, FILE *chat)
{
    char chat_line[1024];
    while (fgets(chat_line, sizeof(chat_line), chat))
    {
        chat_line[strlen(chat_line) - 1] = '\0';
        if (write(clients_filedescriptor, chat_line, strlen(chat_line)) == -1)
        {
            perror("[Server][sending-chat_content()]Error writing the chat history to client.\n");
            exit(EXIT_FAILURE);
        }
        usleep(10000);
    }
    char *eof_marker = "<EOF>";
    if (write(clients_filedescriptor, eof_marker, strlen(eof_marker)) == -1)
    {
        perror("[Server][sending_chat_content()]Error writing the chat history EOF to client.\n");
        exit(EXIT_FAILURE);
    }
}

void writing_the_chat_log(char username[100], FILE *chat, char recieved_message[1024])
{
    char buffer[1024];
    struct timeval message_moment;
    struct tm *tranzit;
    gettimeofday(&message_moment, NULL);
    tranzit = localtime(&message_moment.tv_sec);
    char *time_stamp = asctime(tranzit);
    time_stamp[strlen(time_stamp) - 1] = '\0';
    strcpy(buffer, "[");
    strcat(buffer, username);
    strcat(buffer, "]");
    strcat(buffer, ": ");
    strcat(buffer, recieved_message);
    strcat(buffer, " (");
    strcat(buffer, time_stamp);
    strcat(buffer, ")");
    strcpy(recieved_message, buffer);
    fprintf(chat, "%s\n", recieved_message);
    fflush(chat);
}

void add_to_logged_users(char username[100])
{
    FILE *fd;
    if ((fd = fopen("./logged_users.txt", "a+")) == NULL)
    {
        perror("[Server][add_to_logged_users()]Error Opening the logged_users in append+ mode.\n");
        exit(EXIT_FAILURE);
    }
    fprintf(fd, "%s\n", username);
    fclose(fd);
}

struct uniq_users
{
    char username[100];
};

void remove_user_from_log(char username[100])
{
    struct uniq_users list[20] = {{""}};
    FILE *logged_users_old;
    if ((logged_users_old = fopen("./logged_users.txt", "r")) == NULL)
    {
        perror("[Server][remove_user_from_log()]Erorr trying to open the logged users txt in read mode.\n");
        exit(EXIT_FAILURE);
    }
    char line[1024];
    int i = 0;
    int j;
    int uniq = TRUE;
    while (fgets(line, sizeof(line), logged_users_old))
    {
        line[strlen(line) - 1] = '\0';
        for (j = 0; j < i; ++j)
        {
            if (strcmp(list[j].username, line) == 0)
            {
                uniq = FALSE;
                break;
            }
        }
        if (uniq == TRUE)
        {
            strcpy(list[i].username, line);
            ++i;
        }
        uniq = TRUE;
    }
    int k;
    for (i = 0; i < 20; ++i)
    {
        k = i;
        if (strlen(list[i].username) == 0)
        {
            break;
        }
    }
    for (i = 0; i < k; ++i)
    {
        if (strcmp(list[i].username, username) == 0)
        {
            strcpy(list[i].username, "<REMOVED>");
        }
    }
    fclose(logged_users_old);
    FILE *logged_users_new;
    if ((logged_users_new = fopen("./logged_users.txt", "w")) == NULL)
    {
        perror("[Server][remove_user_from_log()]Erorr trying to open logged_users in write mode to modify it.\n");
        exit(EXIT_FAILURE);
    }
    for (i = 0; i < k; ++i)
    {
        if (strcmp(list[i].username, "<REMOVED>") != 0)
        {
            fprintf(logged_users_new, "%s\n", list[i].username);
        }
    }
    fflush(logged_users_new);
    fclose(logged_users_new);
}

void make_new_chat(char username[100], char user2[100], char new_chat_name[100])
{
    FILE *existence_of_user2;
    if ((existence_of_user2 = fopen("./user_validation.txt", "r")) == NULL)
    {
        perror("[Server][make_new_chat()]Erorr Opening user_validation in read mode to see if user2 exists.\n");
        exit(EXIT_FAILURE);
    }
    char line[1024];
    int exists = FALSE;
    while (fgets(line, sizeof(line), existence_of_user2))
    {
        char *tokken;
        tokken = strtok(line, " ");
        if (strcmp(tokken, user2) == 0)
        {
            exists = TRUE;
            break;
        }
    }
    fclose(existence_of_user2);
    if (exists == FALSE)
    {
        strcpy(new_chat_name, "User doesnt exist\n");
    }
    else
    {
        char chat_name1[200];
        bzero(chat_name1, sizeof(chat_name1));
        strcpy(chat_name1, "./");
        strcat(chat_name1, username);
        strcat(chat_name1, "-");
        strcat(chat_name1, user2);
        strcat(chat_name1, ".txt");
        char chat_name2[200];
        bzero(chat_name2, sizeof(chat_name2));
        strcpy(chat_name2, "./");
        strcat(chat_name2, user2);
        strcat(chat_name2, "-");
        strcat(chat_name2, username);
        strcat(chat_name2, ".txt");
        if (access(chat_name1, F_OK) == 0)
        {
            strcpy(new_chat_name, chat_name1);
        }
        else
        {
            if (access(chat_name2, F_OK) == 0)
            {
                strcpy(new_chat_name, chat_name2);
            }
            else
            {
                FILE *new_chat;
                if ((new_chat = fopen(chat_name1, "w")) == NULL)
                {
                    perror("[Server][make_new_chat()]Error creating the new DM chat.\n");
                    exit(EXIT_FAILURE);
                }
                strcpy(new_chat_name, chat_name1);
                fclose(new_chat);
            }
        }
    }
}

void what_the_client_sees(int clients_filedescriptor, FILE *chat_actualizat)
{
    int counter = count_chat_lines(chat_actualizat);
    sending_chat_content(clients_filedescriptor, chat_actualizat);
    while (TRUE)
    {
        int new_count = count_chat_lines(chat_actualizat);
        if (counter < new_count)
        {
            counter = new_count;
            sending_chat_content(clients_filedescriptor, chat_actualizat);
        }
    }
}

int existence_verifier(FILE *chat, char replied[600])
{
    char line[1024];
    while (fgets(line, sizeof(line), chat))
    {
        line[strlen(line) - 1] = '\0';
        if (strcmp(line, replied) == 0)
        {
            return TRUE;
        }
    }
    return FALSE;
}

void managing_client_side_info_read(char account_clientside[100], int clients_filedescriptor)
{
    FILE *client_side_info_read;
    if ((client_side_info_read = fopen(account_clientside, "r")) == NULL)
    {
        perror("[Server][managing_client_side_info_read()]Erorr opening the clientside chat in read mode.\n");
        exit(EXIT_FAILURE);
    }
    sending_chat_content(clients_filedescriptor, client_side_info_read);
    fclose(client_side_info_read);
}

void client_side_info_write(char account_clientside[100], char *phrase1, char *phrase2, char *phrase3, char *phrase4, char *phrase5, char *phrase6, char *phrase7, char *phrase8, char *phrase9)
{
    FILE *client_side_info_dm_failed_write;
    if ((client_side_info_dm_failed_write = fopen(account_clientside, "w")) == NULL)
    {
        perror("[Server][client_side_info_write()]Erorr opening the clientside chat in write mode.\n");
        exit(EXIT_FAILURE);
    }
    if (strcmp(phrase1, "") != 0)
    {
        fprintf(client_side_info_dm_failed_write, "%s\n", phrase1);
    }
    if (strcmp(phrase2, "") != 0)
    {
        fprintf(client_side_info_dm_failed_write, "%s\n", phrase2);
    }
    if (strcmp(phrase3, "") != 0)
    {
        fprintf(client_side_info_dm_failed_write, "%s\n", phrase3);
    }
    if (strcmp(phrase4, "") != 0)
    {
        fprintf(client_side_info_dm_failed_write, "%s\n", phrase4);
    }
    if (strcmp(phrase5, "") != 0)
    {
        fprintf(client_side_info_dm_failed_write, "%s\n", phrase5);
    }
    if (strcmp(phrase6, "") != 0)
    {
        fprintf(client_side_info_dm_failed_write, "%s\n", phrase6);
    }
    if (strcmp(phrase7, "") != 0)
    {
        fprintf(client_side_info_dm_failed_write, "%s\n", phrase7);
    }
    if (strcmp(phrase8, "") != 0)
    {
        fprintf(client_side_info_dm_failed_write, "%s\n", phrase8);
    }
    if (strcmp(phrase9, "") != 0)
    {
        fprintf(client_side_info_dm_failed_write, "%s\n", phrase9);
    }
    fflush(client_side_info_dm_failed_write);
    fclose(client_side_info_dm_failed_write);
}

void writing_the_report(FILE *chat_reporter, char *reported_message)
{
    fprintf(chat_reporter, "%s\n", reported_message);
}

void bann_hammer_check(char *user_to_be_banned, char *user_to_be_banned_reports)
{
    FILE *reading_reports;
    if ((reading_reports = fopen(user_to_be_banned_reports, "r")) == NULL)
    {
        perror("[Server][bann_hammer_check()]Erorr opening the reports chat for a user to count reports (in read mode).\n");
        exit(EXIT_FAILURE);
    }
    char line[1024];
    int number_of_reports = 0;
    while (fgets(line, sizeof(line), reading_reports))
    {
        number_of_reports += 1;
    }
    if (number_of_reports >= 3)
    { 
        fclose(reading_reports);
        FILE *cleaning_reports;
        if ((cleaning_reports = fopen(user_to_be_banned_reports, "w")) == NULL)
        {
            perror("[Server][bann_hammer_check()]Erorr cleaning the reports of a banned user.\n");
            exit(EXIT_FAILURE);
        }
        fclose(cleaning_reports);
        FILE *ban_list;
        if ((ban_list = fopen("./banned.txt", "a+")) == NULL)
        {
            perror("[Server][bann_hammer_check()]Erorr opening banned file to ban someone (in append+).\n");
            exit(EXIT_FAILURE);
        }
        fprintf(ban_list, "%s\n", user_to_be_banned);
        fflush(ban_list);
        fclose(ban_list);
    }
    else
    {
        fclose(reading_reports);
    }
}

int user_is_banned(char *checked_user)
{
    FILE *ban_list;
    if ((ban_list = fopen("./banned.txt", "r")) == NULL)
    {
        perror("[Server][user_is_banned()]Erorr opening the banned list to see if someone is banend (read mode).\n");
        exit(EXIT_FAILURE);
    }
    char user[1024];
    while (fgets(user, sizeof(user), ban_list))
    {
        user[strlen(user) - 1] = '\0';
        if (strcmp(checked_user, user) == 0)
        {
            fclose(ban_list);
            return TRUE;
        }
    }
    fclose(ban_list);
    return FALSE;
}

int valid_user(char *user_to_be_checked)
{
    FILE *user_validation_file;
    if ((user_validation_file = fopen("./user_validation.txt", "r")) == NULL)
    {
        perror("[Server][valid_user()]Erorr opening the user_validation in read mode.\n");
        exit(EXIT_FAILURE);
    }
    char line[1024];
    while (fgets(line, sizeof(line), user_validation_file))
    {
        char *tokken;
        tokken = strtok(line, " ");
        if (strcmp(tokken, user_to_be_checked) == 0)
        {
            return TRUE;
        }
    }
    return FALSE;
}

int main()
{
    int socket_descriptor;
    if ((socket_descriptor = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("[Server]Error making the Socket.\n");
        return errno;
    }
    int option = 1;
    if (setsockopt(socket_descriptor, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) == -1)
    {
        perror("[Server]Error making the socket Adress Reusable (can bind to it if it is in TIME_WAIT state).\n");
        close(socket_descriptor);
        return errno;
    }

    struct sockaddr_in server_data;
    bzero(&server_data, sizeof(server_data));
    server_data.sin_family = AF_INET;
    server_data.sin_port = htons(PORT);              
    server_data.sin_addr.s_addr = htonl(INADDR_ANY); 
    
    if (bind(socket_descriptor, (struct sockaddr *)&server_data, sizeof(struct sockaddr)) == -1)
    {
        perror("[Server]Error binding.\n");
        close(socket_descriptor);
        return errno;
    }
    
    if (listen(socket_descriptor, 100) == -1)
    { 
        perror("[Serer]Error listening.\n");
        close(socket_descriptor);
        return errno;
    }
    
    while (TRUE)
    {
        struct sockaddr_in client_data;
        bzero(&client_data, sizeof(client_data));
        int clients_filedescriptor;
        socklen_t client_data_length = sizeof(client_data);
        if ((clients_filedescriptor = accept(socket_descriptor, (struct sockaddr *)&client_data, &client_data_length)) == -1)
        {
            perror("[Server]Error accepting the client request.\n");
            close(socket_descriptor);
            return errno;
        }

        pid_t child;
        if ((child = fork()) == -1)
        {
            perror("[Server]Error Forking.\n");
            close(clients_filedescriptor);
            return errno;
        }
        if (child == 0)
        {
            
            struct account client_account;
            if (read(clients_filedescriptor, &client_account, sizeof(client_account)) == -1)
            {
                perror("[Server-child]Error reading the account authentification.\n");
                close(clients_filedescriptor);
                return errno;
            }
            int validate_check;
            if ((validate_check = validate(client_account.username, client_account.password)) != TRUE)
            {
                char *validation_login;
                if (validate_check == FALSE)
                {
                    validation_login = "User doesn't exist";
                }
                else
                {
                    validation_login = "User already logged in";
                }

                if (write(clients_filedescriptor, validation_login, strlen(validation_login)) == -1)
                {
                    perror("[Server-child]Error Writing negative validation response to client.\n");
                    close(clients_filedescriptor);
                    return errno;
                }
            }
            else
            {
                int power_user = FALSE;
                if (strcmp(client_account.username, "admin") == 0)
                {
                    power_user = TRUE;
                }
                char *validation_login;
                if (user_is_banned(client_account.username) == TRUE)
                {
                    validation_login = "User is banned";
                    if (write(clients_filedescriptor, validation_login, strlen(validation_login)) == -1)
                    {
                        perror("[Server-child]Error Writing ban response to client.\n");
                        close(clients_filedescriptor);
                        return errno;
                    }
                    return 0;
                }
                validation_login = "Logged in susccsefully";
                add_to_logged_users(client_account.username);
                if (write(clients_filedescriptor, validation_login, strlen(validation_login)) == -1)
                {
                    perror("[Server-child]Error Writivalid_userng successful validation response to client.\n");
                    close(clients_filedescriptor);
                    return errno;
                }
                
                FILE *chat;
                if ((chat = fopen("./global_chat.txt", "a+")) == NULL)
                {
                    perror("[Server-child]Error opening global_chat.\n");
                    close(clients_filedescriptor);
                    return errno;
                }
                strcpy(current_file_we_in, "./global_chat.txt");
                int make_a_fork = TRUE;
                pid_t sync_child;
                while (TRUE)
                {
                    if (user_is_banned(client_account.username) == TRUE)
                    {
                        char *ban_flag = "You have been banned";
                        kill(sync_child, SIGTERM);
                        fclose(chat);
                        char account_clientside[100];
                        strcpy(account_clientside, "./");
                        strcat(account_clientside, client_account.username);
                        strcat(account_clientside, ".txt");
                        strcpy(current_file_we_in, account_clientside);
                        if ((chat = fopen(account_clientside, "w")) == NULL)
                        {
                            perror("[Server-child]Erorr opening clientside chat for the banned user (in write mode so we clear it).\n");
                            close(clients_filedescriptor);
                            return errno;
                        }
                        fprintf(chat, "%s\n", ban_flag);
                        fflush(chat);
                        fclose(chat);
                        if ((chat = fopen(account_clientside, "a+")) == NULL)
                        {
                            perror("[Server-child]Erorr reopenning clientside chat for banned user (in append mode).\n");
                            close(clients_filedescriptor);
                            return errno;
                        }
                        sending_chat_content(clients_filedescriptor, chat);
                        remove_user_from_log(client_account.username);
                        break;
                    }
                    if (make_a_fork == TRUE)
                    {
                        if ((sync_child = fork()) == -1)
                        {
                            perror("[Server-child]Error makin the sync_child.\n");
                            fclose(chat);
                            close(clients_filedescriptor);
                            return errno;
                        }
                        if (sync_child == 0)
                        {
                            int counter = count_chat_lines(chat);
                            sending_chat_content(clients_filedescriptor, chat);
                            while (TRUE)
                            {
                                int new_count = count_chat_lines(chat);
                                if (counter < new_count)
                                {
                                    counter = new_count;
                                    sending_chat_content(clients_filedescriptor, chat);
                                }
                            }
                        }
                        if (sync_child > 0)
                        {
                            make_a_fork = FALSE;
                        }
                    }
                    int size_of_recieved_message;
                    char recieved_message[1024];
                    if ((size_of_recieved_message = read(clients_filedescriptor, recieved_message, sizeof(recieved_message))) == -1)
                    {
                        perror("[Server-child-common_grounds]Error Reading from client.\n");
                        close(clients_filedescriptor);
                        fclose(chat);
                        return errno;
                    }
                    recieved_message[size_of_recieved_message] = '\0';
                    if (user_is_banned(client_account.username) == FALSE)
                    {
                        if (size_of_recieved_message > 0)
                        {
                            char *tokken;
                            char buffer[1024];
                            strcpy(buffer, recieved_message);
                            tokken = strtok(buffer, " "); 
                            if (strcmp(tokken, "exit()") == 0)
                            {
                                remove_user_from_log(client_account.username);
                                break;
                            }
                            else
                            {
                                if (strcmp(tokken, "help()") == 0)
                                {
                                    if (power_user == TRUE)
                                    {
                                        char account_clientside[100];
                                        strcpy(account_clientside, "./");
                                        strcat(account_clientside, client_account.username);
                                        strcat(account_clientside, ".txt");
                                        client_side_info_write(account_clientside, "DM <username> -> start a conversation with username\n",
                                                               "global_chat() -> to return to the global chat room\n",
                                                               "users() -> to show all users and their status\n",
                                                               "reply_to() <<Message you want to reply to(copy it from the terminal)>> <Message you wish to reply with> -> to reply to someone's message\n",
                                                               "report() <<Message that you wish to report>> -> to report someone for a message they sent\n",
                                                               "banned() -> to see the list of banned people IF there are any\n",
                                                               "ban() <Username> -> to ban that user\n",
                                                               "unban() <Username> -> to unban that user\n",
                                                               "exit() -> to exit and logout\n");
                                        managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                    }
                                    else
                                    {
                                        char account_clientside[100];
                                        strcpy(account_clientside, "./");
                                        strcat(account_clientside, client_account.username);
                                        strcat(account_clientside, ".txt");
                                        client_side_info_write(account_clientside, "DM <username> -> start a conversation with username\n",
                                                               "global_chat() -> to return to the global chat room\n",
                                                               "users() -> to show all users and their status\n",
                                                               "reply_to() <<Message you want to reply to(copy it from the terminal)>> <Message you wish to reply with> -> to reply to someone's message\n",
                                                               "report() <<Message that you wish to report>> -> to report someone for a message they sent\n",
                                                               "exit() -> to exit and logout\n",
                                                               "",
                                                               "",
                                                               "");
                                        managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                    }
                                }
                                else
                                {
                                    if (strcmp(tokken, "users()") == 0)
                                    {
                                        char account_clientside[100];
                                        strcpy(account_clientside, "./");
                                        strcat(account_clientside, client_account.username);
                                        strcat(account_clientside, ".txt");
                                        FILE *client_side_info_write_file;
                                        if ((client_side_info_write_file = fopen(account_clientside, "w")) == NULL)
                                        {
                                            perror("[Server-child-common_grounds-users()]Erorr opening the clientside chat in write mode.\n");
                                            close(clients_filedescriptor);
                                            fclose(chat);
                                            return errno;
                                        }
                                        char check_line[1024];
                                        FILE *user_validation;
                                        if ((user_validation = fopen("./user_validation.txt", "r")) == NULL)
                                        {
                                            perror("[Server-child-common_grounds-users()]Erorr opening user validation to get all the users (read mode).\n");
                                            close(clients_filedescriptor);
                                            fclose(chat);
                                            fclose(client_side_info_write_file);
                                            return errno;
                                        }
                                        while (fgets(check_line, sizeof(check_line), user_validation))
                                        {
                                            check_line[strlen(check_line) - 1] = '\0';
                                            char *tokk;
                                            tokk = strtok(check_line, " ");
                                            char logged_line[1024];
                                            FILE *logged_users;
                                            if ((logged_users = fopen("./logged_users.txt", "r")) == NULL)
                                            {
                                                perror("[Server-child-common_grounds-users()]Erorr opening logged_users to see who is online .\n");
                                                close(clients_filedescriptor);
                                                fclose(chat);
                                                fclose(client_side_info_write_file);
                                                fclose(logged_users);
                                                return errno;
                                            }
                                            int online = FALSE;
                                            while (fgets(logged_line, sizeof(logged_line), logged_users))
                                            {
                                                logged_line[strlen(logged_line) - 1] = '\0';
                                                if (strcmp(tokk, logged_line) == 0)
                                                {
                                                    online = TRUE;
                                                }
                                            }
                                            if (online == TRUE)
                                            {
                                                fprintf(client_side_info_write_file, "%s       online\n", tokk);
                                                fflush(client_side_info_write_file);
                                            }
                                            else
                                            {
                                                fprintf(client_side_info_write_file, "%s       offline\n", tokk);
                                                fflush(client_side_info_write_file);
                                            }
                                            fclose(logged_users);
                                        }
                                        fclose(client_side_info_write_file);
                                        fclose(user_validation);
                                        managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                    }
                                    else
                                    {
                                        if (strcmp(tokken, "DM") == 0)
                                        {
                                            char user1[100];
                                            tokken = strtok(NULL, " ");
                                            strcpy(user1, tokken);
                                            char new_chat[100];
                                            make_new_chat(client_account.username, user1, new_chat); 
                                            if (strcmp(new_chat, "User doesnt exist\n") == 0)
                                            {
                                                char account_clientside[100];
                                                strcpy(account_clientside, "./");
                                                strcat(account_clientside, client_account.username);
                                                strcat(account_clientside, ".txt");
                                                client_side_info_write(account_clientside, new_chat, "", "", "", "", "", "", "", "");
                                                managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                            }
                                            else
                                            {
                                                fclose(chat);
                                                if ((chat = fopen(new_chat, "a+")) == NULL)
                                                {
                                                    perror("[Server-child-common_grounds-DM()]Error opening the NEW chat in append+ mode.\n");
                                                    close(clients_filedescriptor);
                                                    return errno;
                                                }
                                                strcpy(current_file_we_in, new_chat);
                                                kill(sync_child, SIGTERM);
                                                make_a_fork = TRUE;
                                            }
                                        }
                                        else
                                        {
                                            if (strcmp(tokken, "global_chat()") == 0)
                                            {
                                                fclose(chat);
                                                if ((chat = fopen("./global_chat.txt", "a+")) == NULL)
                                                {
                                                    perror("[Server-child-common_grounds-global_chat()]Error opening the global chat.\n");
                                                    close(clients_filedescriptor);
                                                    return errno;
                                                }
                                                strcpy(current_file_we_in, "./global_chat.txt");
                                                kill(sync_child, SIGTERM);
                                                make_a_fork = TRUE;
                                            }
                                            else
                                            {
                                                if (strcmp(tokken, "reply_to()") == 0)
                                                {
                                                    fclose(chat);
                                                    if ((chat = fopen(current_file_we_in, "a+")) == NULL) 
                                                    {
                                                        perror("[Server-child-common_grounds-reply_to()]Error reopening the chat we are currently in (append+ mode).\n");
                                                        close(clients_filedescriptor);
                                                        return errno;
                                                    }
                                                    char reply[11], replied[600], message[400], the_formated_one[1024];
                                                    if (sscanf(recieved_message, "%s <%[^>]> %[^\n]", reply, replied, message) == 3)
                                                    { 
                                                        int existance = existence_verifier(chat, replied);
                                                        if (existance == TRUE)
                                                        {
                                                            strcpy(the_formated_one, "Replied to (");
                                                            strcat(the_formated_one, replied);
                                                            strcat(the_formated_one, ") with : ");
                                                            strcat(the_formated_one, message);
                                                            writing_the_chat_log(client_account.username, chat, the_formated_one);
                                                        }
                                                        else
                                                        {
                                                            char account_clientside[100];
                                                            strcpy(account_clientside, "./");
                                                            strcat(account_clientside, client_account.username);
                                                            strcat(account_clientside, ".txt");
                                                            client_side_info_write(account_clientside, "The message you wish to reply to Doesn't exist\n", "", "", "", "", "", "", "", "");
                                                            managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                                        }
                                                    }
                                                    else
                                                    {
                                                        char account_clientside[100];
                                                        strcpy(account_clientside, "./");
                                                        strcat(account_clientside, client_account.username);
                                                        strcat(account_clientside, ".txt");
                                                        client_side_info_write(account_clientside, "Failed to Reply\n", "", "", "", "", "", "", "", "");
                                                        managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                                    }
                                                }
                                                else
                                                {
                                                    if (strcmp(tokken, "report()") == 0)
                                                    {
                                                        fclose(chat);
                                                        if ((chat = fopen(current_file_we_in, "a+")) == NULL)
                                                        {
                                                            perror("[Server-child-common_grounds-report()]Error reopening the chat we are currently in (append+ mode).\n");
                                                            close(clients_filedescriptor);
                                                            return errno;
                                                        }
                                                        char report[11], reported_message[600];
                                                        if (sscanf(recieved_message, "%s <%[^>]>", report, reported_message) == 2)
                                                        { 
                                                            int existance = existence_verifier(chat, reported_message);
                                                            if (existance == TRUE)
                                                            {
                                                                char account_clientside[100];
                                                                strcpy(account_clientside, "./");
                                                                strcat(account_clientside, client_account.username);
                                                                strcat(account_clientside, ".txt");
                                                                char reported_user[1024]; 
                                                                sscanf(reported_message, "[%[^]]", reported_user);
                                                                char user_report[1024];
                                                                if (strcmp(reported_user, client_account.username) == 0)
                                                                {
                                                                    client_side_info_write(account_clientside, "Why would you want to report yourself??\n", "", "", "", "", "", "", "", "");
                                                                    managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                                                }
                                                                else
                                                                {
                                                                    if (strcmp(reported_user, "admin") == 0)
                                                                    {
                                                                        client_side_info_write(account_clientside, "Can not report the admin :D\n", "", "", "", "", "", "", "", "");
                                                                        managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                                                    }
                                                                    else
                                                                    {
                                                                        strcpy(user_report, "./");
                                                                        strcat(user_report, reported_user);
                                                                        strcat(user_report, "_Reports.txt");
                                                                        FILE *chat_reporter;
                                                                        if ((chat_reporter = fopen(user_report, "a+")) == NULL)
                                                                        {
                                                                            perror("[Server-child-common_grounds-report()]Erorr opening the user_Reports chat in append+ mode.\n");
                                                                            close(clients_filedescriptor);
                                                                            fclose(chat);
                                                                            return errno;
                                                                        }
                                                                        existance = existence_verifier(chat_reporter, reported_message);
                                                                        if (user_is_banned(reported_user) == TRUE)
                                                                        {
                                                                            fclose(chat_reporter);
                                                                            client_side_info_write(account_clientside, "User is already banned\n", "", "", "", "", "", "", "", "");
                                                                            managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                                                        }
                                                                        else
                                                                        {
                                                                            if (existance == FALSE)
                                                                            {

                                                                                writing_the_report(chat_reporter, reported_message);
                                                                                fclose(chat_reporter);
                                                                                bann_hammer_check(reported_user, user_report);
                                                                                client_side_info_write(account_clientside, "Succesfully reported\n", "", "", "", "", "", "", "", "");
                                                                                managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                                                            }
                                                                            else
                                                                            {
                                                                                fclose(chat_reporter);
                                                                                bann_hammer_check(reported_user, user_report);
                                                                                char account_clientside[100];
                                                                                strcpy(account_clientside, "./");
                                                                                strcat(account_clientside, client_account.username);
                                                                                strcat(account_clientside, ".txt");
                                                                                client_side_info_write(account_clientside, "Message already reported\n", "", "", "", "", "", "", "", "");
                                                                                managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            else
                                                            {
                                                                char account_clientside[100];
                                                                strcpy(account_clientside, "./");
                                                                strcat(account_clientside, client_account.username);
                                                                strcat(account_clientside, ".txt");
                                                                client_side_info_write(account_clientside, "The message you wish to report doesn't exist\n", "", "", "", "", "", "", "", "");
                                                                managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                                            }
                                                        }
                                                        else
                                                        {
                                                            char account_clientside[100];
                                                            strcpy(account_clientside, "./");
                                                            strcat(account_clientside, client_account.username);
                                                            strcat(account_clientside, ".txt");
                                                            client_side_info_write(account_clientside, "Failed to Report\n", "", "", "", "", "", "", "", "");
                                                            managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                                        }
                                                    }
                                                    else
                                                    {
                                                        if ((strcmp(tokken, "banned()") == 0) && (power_user == TRUE))
                                                        {
                                                            char account_clientside[100];
                                                            strcpy(account_clientside, "./banned.txt");
                                                            managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                                        }
                                                        else
                                                        {
                                                            if ((strcmp(tokken, "unban()") == 0) && (power_user == TRUE))
                                                            {
                                                                char user_to_be_ubanned[100];
                                                                tokken = strtok(NULL, " ");
                                                                if (tokken == NULL)
                                                                {
                                                                    char account_clientside[100] = "./admin.txt";
                                                                    client_side_info_write(account_clientside, "Who do you want to unban?\n", "", "", "", "", "", "", "", "");
                                                                    managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                                                }
                                                                else
                                                                {
                                                                    strcpy(user_to_be_ubanned, tokken);
                                                                    FILE *ban_list;
                                                                    if ((ban_list = fopen("./banned.txt", "r")) == NULL)
                                                                    {
                                                                        perror("[Server-child-common_grounds-unban()]Error opening the banned file to read for unbaning.\n");
                                                                        close(clients_filedescriptor);
                                                                        fclose(chat);
                                                                        return errno;
                                                                    }
                                                                    FILE *temp;
                                                                    if ((temp = fopen("./temporary.txt", "w")) == NULL)
                                                                    {
                                                                        perror("[Server-child-common_grounds-unban()]Error opening temporary file in write mode to unban.\n");
                                                                        close(clients_filedescriptor);
                                                                        fclose(chat);
                                                                        fclose(ban_list);
                                                                        return errno;
                                                                    }
                                                                    int lines1 = 0;
                                                                    int user_was_removed = FALSE;
                                                                    char line[1024];
                                                                    while (fgets(line, sizeof(line), ban_list))
                                                                    {
                                                                        line[strlen(line) - 1] = '\0';
                                                                        if (strcmp(user_to_be_ubanned, line) != 0)
                                                                        {
                                                                            lines1 += 1;
                                                                            fprintf(temp, "%s\n", line);
                                                                            fflush(temp);
                                                                        }
                                                                        else
                                                                        {
                                                                            user_was_removed = TRUE;
                                                                        }
                                                                    }
                                                                    fclose(ban_list);
                                                                    fclose(temp);
                                                                    if ((ban_list = fopen("./banned.txt", "w")) == NULL)
                                                                    {
                                                                        perror("[Server-child-common_grounds-unban()]Error opening the banned file to clear it for unbaning.\n");
                                                                        close(clients_filedescriptor);
                                                                        fclose(chat);
                                                                        return errno;
                                                                    }
                                                                    if (lines1 > 0)
                                                                    {
                                                                        if ((temp = fopen("./temporary.txt", "r")) == NULL)
                                                                        {
                                                                            perror("[Server-child-common_grounds-unban()]Error opening temporary file in read mode to unban.\n");
                                                                            close(clients_filedescriptor);
                                                                            fclose(chat);
                                                                            fclose(ban_list);
                                                                            return errno;
                                                                        }
                                                                        while (fgets(line, sizeof(line), temp))
                                                                        {
                                                                            line[strlen(line) - 1] = '\0';
                                                                            fprintf(ban_list, "%s\n", line);
                                                                        }
                                                                        fclose(temp);
                                                                    }
                                                                    if (user_was_removed == FALSE)
                                                                    {
                                                                        fclose(ban_list);
                                                                        char account_clientside[100] = "./admin.txt";
                                                                        client_side_info_write(account_clientside, "This user isn't banned\n", "", "", "", "", "", "", "", "");
                                                                        managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                                                    }
                                                                    else
                                                                    {
                                                                        fclose(ban_list);
                                                                        strcpy(user_to_be_ubanned, "./banned.txt"); 
                                                                        managing_client_side_info_read(user_to_be_ubanned, clients_filedescriptor);
                                                                    }
                                                                }
                                                            }
                                                            else
                                                            {
                                                                if ((strcmp(tokken, "ban()") == 0)&& (power_user==TRUE))
                                                                {
                                                                    tokken = strtok(NULL, " ");
                                                                    if (tokken == NULL)
                                                                    {
                                                                        char account_clientside[100] = "./admin.txt";
                                                                        client_side_info_write(account_clientside, "Who do you wanna ban?\n", "", "", "", "", "", "", "", "");
                                                                        managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                                                    }
                                                                    else
                                                                    {
                                                                        if (valid_user(tokken) == TRUE)
                                                                        {
                                                                            if (strcmp(tokken, "admin") == 0)
                                                                            {
                                                                                char account_clientside[100] = "./admin.txt";
                                                                                client_side_info_write(account_clientside, "Really...\n", "Wanna ban yourself?\n", "", "", "", "", "", "", "");
                                                                                managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                                                            }
                                                                            else
                                                                            {
                                                                                if (user_is_banned(tokken) == TRUE)
                                                                                {
                                                                                    char account_clientside[100] = "./admin.txt";
                                                                                    client_side_info_write(account_clientside, "This user is already banned , cut him some slack\n", "", "", "", "", "", "", "", "");
                                                                                    managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                                                                }
                                                                                else
                                                                                {
                                                                                    FILE *ban_file;
                                                                                    if ((ban_file = fopen("./banned.txt", "a+")) == NULL)
                                                                                    {
                                                                                        perror("[Server-child-common_grounds-ban()]Error opening the banned file in append+ mode.\n");
                                                                                        close(clients_filedescriptor);
                                                                                        fclose(chat);
                                                                                        return errno;
                                                                                    }
                                                                                    fprintf(ban_file, "%s\n", tokken);
                                                                                    fflush(ban_file);
                                                                                    fclose(ban_file);
                                                                                    char reportred_user_reports[1024];
                                                                                    strcpy(reportred_user_reports, "./");
                                                                                    strcat(reportred_user_reports, tokken);
                                                                                    strcat(reportred_user_reports, "_Reports.txt");
                                                                                    FILE *cleaning_reports;
                                                                                    if ((cleaning_reports = fopen(reportred_user_reports, "w")) == NULL)
                                                                                    {
                                                                                        perror("[Server-child-common_grounds-ban()]Erorr cleaning the reports of a banned user banned by admin.\n");
                                                                                        close(clients_filedescriptor);
                                                                                        fclose(chat);
                                                                                        return errno;
                                                                                    }
                                                                                    fclose(cleaning_reports);
                                                                                    char account_clientside[100] = "./banned.txt";
                                                                                    managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                                                                }
                                                                            }
                                                                        }
                                                                        else
                                                                        {
                                                                            char account_clientside[100] = "./admin.txt";
                                                                            client_side_info_write(account_clientside, "This user doesnt exist , so you can't ban him , don't be power hungry\n", "", "", "", "", "", "", "", "");
                                                                            managing_client_side_info_read(account_clientside, clients_filedescriptor);
                                                                        }
                                                                    }
                                                                }
                                                                else
                                                                {
                                                                    writing_the_chat_log(client_account.username, chat, recieved_message);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if (kill(sync_child, SIGTERM) == -1)
                {
                    if (errno == ESRCH)
                    {
                        printf("The Process is already DEAD\n");
                    }
                    else
                    {
                        perror("[Server-child-common_grounds]Error Killing the child.\n");
                        return errno;
                    }
                }
                int process_status;
                if (waitpid(sync_child, &process_status, 0) == -1)
                {
                    perror("[Server-child-common_grounds]Error waiting for process ID.\n");
                    return errno;
                }
                else
                {
                    printf("Processes stopped succesfully\n");
                }
                fclose(chat);
                close(clients_filedescriptor);
            }
        }
        if (child > 0)
        {
            close(clients_filedescriptor);
        }
    }
}
