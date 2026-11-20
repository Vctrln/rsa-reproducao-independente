/*
 * rusage_exec <arquivo_saida> <programa> [args...]
 *
 * Executa o programa como FILHO deste processo mínimo e grava em <arquivo_saida> o rusage dele:
 *   "<ru_maxrss_kB> <ru_utime_s> <ru_stime_s>"
 * Sai com o mesmo código do programa (ou 128+sinal).
 *
 * Por que existe: no Linux, o ru_maxrss de um processo herda o pico de memória do pai através de fork/exec.
 * Medido direto do orquestrador Python (~120 MB), todos os programas apareciam com o RSS do orquestrador. Aqui o
 * fork parte de um processo pequeno, e o valor medido é o do programa medido. Usado só como EXTENSÃO
 * (o artigo não mede consumo de memória); não interfere no tempo, que cada programa mede internamente.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "uso: rusage_exec <saida> <programa> [args...]\n");
        return 2;
    }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 2; }
    if (pid == 0) {
        execvp(argv[2], argv + 2);
        perror("execvp");
        _exit(127);
    }
    int status;
    struct rusage ru;
    if (wait4(pid, &status, 0, &ru) < 0) { perror("wait4"); return 2; }
    FILE *f = fopen(argv[1], "w");
    if (f) {
        fprintf(f, "%ld %.6f %.6f\n", ru.ru_maxrss, ru.ru_utime.tv_sec + ru.ru_utime.tv_usec * 1e-6,
                ru.ru_stime.tv_sec + ru.ru_stime.tv_usec * 1e-6);
        fclose(f);
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 128 + WTERMSIG(status);
}
