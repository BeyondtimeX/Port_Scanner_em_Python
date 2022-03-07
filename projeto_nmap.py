import nmap

scanner = nmap.PortScanner()

print('\n')
print('-=' * 18)
print('\tSnanner de Portas')
print('-=' * 18)

ip = input('\nEntre com o IP a ser varrido: ')

while True:
    
    menu = int(input('\nEscolha o tipo de varredura a ser realizado:\n\t<1> Varredura do tipo SYN\n\t<2> Varredura do tipo UDP'
                    '\n\t<3> Varredura do tipo intenso\n\t<4> Mudar o IP\n\t<0> Sair\n\tDigite a opção escolhida: '))

    if menu == 1:
        print('\nVersão no NMAP: ', scanner.nmap_version())
        scanner.scan(ip, '1-1024', '-sS')
        print(scanner.scaninfo())
        print('Status do IP: ',scanner[ip].state())
        print(scanner[ip].all_protocols())
        print('\nPortas Abertas: ', scanner[ip]['tcp'].keys(),'\n')

    elif menu == 2:
        print('\nVersão no NMAP: ', scanner.nmap_version())
        scanner.scan(ip, '1-1024', '-sU')
        print(scanner.scaninfo())
        print('Status do IP: ',scanner[ip].state())
        print(scanner[ip].all_protocols())
        print('\nPortas Abertas: ', scanner[ip]['udp'].keys(),'\n')

    elif menu == 3:
        print('\nVersão no NMAP: ', scanner.nmap_version())
        scanner.scan(ip, '1-1024', '-sC')
        print(scanner.scaninfo())
        print('Status do IP: ',scanner[ip].state())
        print(scanner[ip].all_protocols())
        print('\nPortas Abertas: ', scanner[ip]['tcp'].keys(),'\n')

    elif menu == 4:
        ip = input('\nEntre com o IP ou Hostname a ser varrido: ')

    elif menu == 0:
        print('\nFim do Programa.\n')
        break

    else:
        print('Opção inválida, escolha uma das opções solicitadas.')