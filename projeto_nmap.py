import nmap
import re

def imprimir_cabecalho():
    """Imprime o cabeçalho do programa."""
    print('\n' + '-=' * 18)
    print('\tScanner de Portas')
    print('-=' * 18)

def solicitar_ip():
    """Solicita e retorna um IP ou hostname válido do usuário."""
    while True:
        ip = input('\nEntre com o IP ou Hostname a ser varrido: ')
        if validar_ip(ip):
            return ip
        else:
            print('IP ou Hostname inválido. Por favor, tente novamente.')

def validar_ip(ip):
    """Valida se o IP ou hostname fornecido é válido."""
    ip_pattern = re.compile(
        r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"  # Formato de IPv4
        r"|^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*"  # Formato de hostname
        r"([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
    )
    return re.match(ip_pattern, ip) is not null

def exibir_menu():
    """Exibe o menu de opções e retorna a escolha do usuário."""
    while True:
        try:
            escolha = int(input('\nEscolha o tipo de varredura a ser realizado:\n'
                                '\t<1> Varredura do tipo SYN\n'
                                '\t<2> Varredura do tipo UDP\n'
                                '\t<3> Varredura do tipo intensa\n'
                                '\t<4> Mudar o IP\n'
                                '\t<5> Salvar resultados em log\n'
                                '\t<0> Sair\n'
                                '\tDigite a opção escolhida: '))
            if escolha in range(0, 6):
                return escolha
            else:
                print('Opção inválida, por favor digite um número entre 0 e 5.')
        except ValueError:
            print('Opção inválida, por favor digite um número entre 0 e 5.')

def realizar_varredura(ip, tipo_varredura, protocolo):
    """Realiza a varredura no IP fornecido usando o tipo de varredura especificado e imprime os resultados."""
    print('\nVersão do NMAP: ', scanner.nmap_version())
    scanner.scan(ip, '1-1024', tipo_varredura)
    print(scanner.scaninfo())
    print('Status do IP: ', scanner[ip].state())
    protocolos = scanner[ip].all_protocols()
    print('Protocolos encontrados: ', protocolos)
    if protocolo in protocolos:
        portas_abertas = list(scanner[ip][protocolo].keys())
        print('\nPortas Abertas: ', portas_abertas, '\n')
        return portas_abertas
    else:
        print(f'Nenhuma porta {protocolo} aberta encontrada.\n')
        return []

def salvar_resultados(ip, resultados):
    """Salva os resultados da varredura em um arquivo de log."""
    with open("resultados_varredura.txt", "a") as file:
        file.write(f"\nResultados da varredura para o IP: {ip}\n")
        for tipo, portas in resultados.items():
            file.write(f"\nTipo de Varredura: {tipo}\n")
            file.write(f"Portas Abertas: {portas}\n")
        file.write("-" * 40 + "\n")
    print('Resultados salvos no arquivo resultados_varredura.txt')

def main():
    """Função principal que executa o fluxo do programa."""
    global scanner
    scanner = nmap.PortScanner()
    imprimir_cabecalho()
    ip = solicitar_ip()
    resultados = {}

    while True:
        menu = exibir_menu()

        if menu == 1:
            resultados['SYN'] = realizar_varredura(ip, '-sS', 'tcp')
        elif menu == 2:
            resultados['UDP'] = realizar_varredura(ip, '-sU', 'udp')
        elif menu == 3:
            resultados['Intensa'] = realizar_varredura(ip, '-sC', 'tcp')
        elif menu == 4:
            ip = solicitar_ip()
            resultados = {}  # Resetar resultados ao mudar de IP
        elif menu == 5:
            salvar_resultados(ip, resultados)
        elif menu == 0:
            print('\nFim do Programa.\n')
            break

if __name__ == "__main__":
    main()
