import nmap

# Inicializando o scanner
scanner = nmap.PortScanner()

# Cabeçalho do programa
print('\n' + '-=' * 18)
print('\tScanner de Portas')
print('-=' * 18)

# Solicitação inicial do IP
ip = input('\nEntre com o IP ou Hostname a ser varrido: ')

def realizar_varredura(ip, tipo_varredura, protocolo):
    print('\nVersão do NMAP: ', scanner.nmap_version())
    scanner.scan(ip, '1-1024', tipo_varredura)
    print(scanner.scaninfo())
    print('Status do IP: ', scanner[ip].state())
    protocolos = scanner[ip].all_protocols()
    print('Protocolos encontrados: ', protocolos)
    if protocolo in protocolos:
        print('\nPortas Abertas: ', scanner[ip][protocolo].keys(), '\n')
    else:
        print(f'Nenhuma porta {protocolo} aberta encontrada.\n')

while True:
    # Exibindo menu de opções
    try:
        menu = int(input('\nEscolha o tipo de varredura a ser realizado:\n\t<1> Varredura do tipo SYN\n\t<2> Varredura do tipo UDP'
                         '\n\t<3> Varredura do tipo intenso\n\t<4> Mudar o IP\n\t<0> Sair\n\tDigite a opção escolhida: '))
    except ValueError:
        print('Opção inválida, por favor digite um número entre 0 e 4.')
        continue

    if menu == 1:
        # Varredura do tipo SYN
        realizar_varredura(ip, '-sS', 'tcp')

    elif menu == 2:
        # Varredura do tipo UDP
        realizar_varredura(ip, '-sU', 'udp')

    elif menu == 3:
        # Varredura intensa
        realizar_varredura(ip, '-sC', 'tcp')

    elif menu == 4:
        # Mudança de IP
        ip = input('\nEntre com o novo IP ou Hostname a ser varrido: ')

    elif menu == 0:
        # Finalização do programa
        print('\nFim do Programa.\n')
        break

    else:
        print('Opção inválida, escolha uma das opções solicitadas.')
