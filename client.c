#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>

#define PORT 2500
#define HOST "127.0.0.1"
#define TRUE 1
#define FALSE 0

struct account
{
    char username[100];
    char password[100];
};

int print_history(int descriptor)
{
    int clear = TRUE;
    while (TRUE)
    {
        char chat_line[1024];
        int dimensiune_chat_history = read(descriptor, chat_line, sizeof(chat_line));
        if (dimensiune_chat_history < 0)
        {
            perror("[Client][print_history]Error reading the chat history.\n");
            exit(EXIT_FAILURE);
        }
        if (clear == TRUE)
        {
            system("clear");
            clear = FALSE;
        }
        if (dimensiune_chat_history == 0)
        {
            break;
        }
        chat_line[dimensiune_chat_history] = '\0';
        if (strcmp(chat_line, "You have been banned") == 0)
        {
            printf("You have been Banend\nPress anything to exit\n");
            return FALSE;
        }

        if (strcmp(chat_line, "<EOF>") == 0)
        {
            break;
        }
        printf("%s\n", chat_line);
        fflush(stdout);
        usleep(10000);
    }
    return TRUE;
}

int main()
{
    int socket_descriptor;
    if ((socket_descriptor = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("[Client]Error making the Socket.\n");
        return errno;
    }

    struct sockaddr_in server_connector;
    bzero(&server_connector, sizeof(server_connector));
    server_connector.sin_family = AF_INET;
    server_connector.sin_port = htons(PORT);
    server_connector.sin_addr.s_addr = inet_addr(HOST);

    if (connect(socket_descriptor, (struct sockaddr *)&server_connector, sizeof(struct sockaddr)) == -1)
    {
        perror("[Client]Error conecting to the server.\n");
        return errno;
    }
    printf("After logging in use <help()> for the command list\n");
    printf("Type <Username> <password> to connect to the server\n");
    struct account user_account;
    char account_string[1024];
    if (fgets(account_string, sizeof(account_string), stdin) == NULL)
    {
        perror("[Client]Error reading from stdin for Loging in.\n");
        close(socket_descriptor);
        return errno;
    }
    sscanf(account_string, "%s %s", user_account.username, user_account.password);
    if (write(socket_descriptor, &user_account, sizeof(user_account)) == -1)
    {
        perror("[Client]Error writing to server.\n");
        close(socket_descriptor);
        return errno;
    }
    int recieved_message_size;
    char recieved_message[1024];
    if ((recieved_message_size = read(socket_descriptor, recieved_message, sizeof(recieved_message))) == -1)
    {
        perror("[Client]Error reading the feedback from server.\n");
        close(socket_descriptor);
        return errno;
    }
    recieved_message[recieved_message_size] = '\0';
    printf("%s\n", recieved_message);
    if (strcmp(recieved_message, "Logged in susccsefully") == 0)
    {
        pid_t sync_child;
        if ((sync_child = fork()) == -1)
        {
            perror("[Client]Error forking for sync");
            close(socket_descriptor);
            return errno;
        }
        if (sync_child == 0)
        {
            while (TRUE)
            {
                if (print_history(socket_descriptor) == FALSE)
                {
                    break;
                }
                printf("[%s]: ", user_account.username);
                fflush(stdout);
            }
            close(socket_descriptor);
            exit(0);
        }
        if (sync_child > 0)
        {
            while (TRUE)
            {
                int status_of_child;
                pid_t verdict;
                verdict = waitpid(sync_child, &status_of_child, WNOHANG);
                if (verdict == -1)
                {
                    perror("[Client-father]Erorr waiting for child termination.\n");
                    close(socket_descriptor);
                    return errno;
                }
                if (verdict > 0)
                {
                    close(socket_descriptor);
                    break;
                }
                char read_from_stdin[1024];
                if (fgets(read_from_stdin, sizeof(read_from_stdin), stdin) == NULL)
                {
                    perror("[Client-father]Error reading from stdin.\n");
                    close(socket_descriptor);
                    return errno;
                }
                read_from_stdin[strlen(read_from_stdin) - 1] = '\0';
                if (strcmp(read_from_stdin, "exit()") == 0)
                {
                    if (write(socket_descriptor, read_from_stdin, strlen(read_from_stdin)) == -1)
                    {
                        perror("[Client-father-exit()]Error writing to server");
                        close(socket_descriptor);
                        return errno;
                    }
                    break;
                }
                else
                {
                    if (write(socket_descriptor, read_from_stdin, strlen(read_from_stdin)) == -1)
                    {
                        perror("[Client-father]Error writing to server");
                        close(socket_descriptor);
                        return errno;
                    }
                }
            }
            kill(sync_child, SIGTERM);
        }
    }
    close(socket_descriptor);
}