import base64
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from colorama import Fore, Style, init
import pyperclip
import glob
import time
from tqdm import tqdm
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import secrets
import getpass

init(autoreset=True)
os.system("title Base69 v3.2 Pro - AES-256 + HMAC Enhanced")

BANNER = f"""{Fore.CYAN}
██████╗  █████╗ ███████╗███████╗     ██████╗ █████╗ 
██╔══██╗██╔══██╗██╔════╝██╔════╝    ██╔════╝██╔══██╗
██████╔╝███████║███████╗█████╗      ███████╗╚██████║
██╔══██╗██╔══██║╚════██║██╔══╝      ██╔═══██╗╚═══██║
██████╔╝██║  ██║███████║███████╗    ╚██████╔╝█████╔╝
╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝     ╚═════╝ ╚════╝ 
{Fore.LIGHTYELLOW_EX}►► Codificação Híbrida V3.2 (AES-256 + Vigenère + HMAC) ◄◄
{Fore.LIGHTBLACK_EX}Versão 3.2 | by: github.com/MrRonak
{Style.RESET_ALL}"""

SEPARADOR = f"{Fore.LIGHTBLACK_EX}{'-' * 60}"


def aplicar_rot13(texto: str) -> str:
    return texto.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))


def cifra_vigenere(texto: str, chave: str, modo: str) -> str:
    resultado = []
    chave = chave.upper().replace(" ", "")
    chave_extendida = (chave * (len(texto) // len(chave) + 1))[:len(texto)]

    for i, char in enumerate(texto):
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            deslocamento = ord(chave_extendida[i]) - ord('A')
            if modo == 'decodificar':
                deslocamento = -deslocamento
            novo_char = chr((ord(char) - offset + deslocamento) % 26 + offset)
            resultado.append(novo_char)
        else:
            resultado.append(char)
    return ''.join(resultado)


def codificacao_avancada(texto: str, chave_xor: str) -> str:
    passo1 = base64.b64encode(texto.encode()).decode()
    passo2 = aplicar_rot13(passo1)
    passo3 = ''.join(format(ord(c), '08b') for c in passo2)
    xor_bits = [str(int(bit) ^ (ord(chave_xor[i % len(chave_xor)]) % 2)) for i, bit in enumerate(passo3)]
    bytes_finais = bytes(int(''.join(xor_bits[i:i + 8]), 2) for i in range(0, len(xor_bits), 8))
    return base64.b64encode(bytes_finais).decode()


def decodificacao_avancada(texto_codificado: str, chave_xor: str) -> str:
    bytes_iniciais = base64.b64decode(texto_codificado)
    binario = ''.join(format(byte, '08b') for byte in bytes_iniciais)
    xor_revertido = [str(int(bit) ^ (ord(chave_xor[i % len(chave_xor)]) % 2)) for i, bit in enumerate(binario)]
    binario_revertido = ''.join(xor_revertido)
    texto_rot13 = ''.join(chr(int(binario_revertido[i:i + 8], 2)) for i in range(0, len(binario_revertido), 8))
    texto_base64 = aplicar_rot13(texto_rot13)
    return base64.b64decode(texto_base64).decode()


def gerar_hmac(dados: str, chave_hmac: str) -> str:
    """Gera um HMAC SHA-256 para autenticação dos dados"""
    hmac_obj = hmac.new(
        chave_hmac.encode(),
        dados.encode(),
        hashlib.sha256
    )
    return base64.b64encode(hmac_obj.digest()).decode()


def verificar_hmac(dados: str, chave_hmac: str, hmac_recebido: str) -> bool:
    """Verifica se o HMAC recebido corresponde aos dados"""
    hmac_calculado = gerar_hmac(dados, chave_hmac)
    return hmac.compare_digest(hmac_calculado, hmac_recebido)


def derivar_chave_aes(senha: str, salt: bytes = None) -> tuple:
    """
    Deriva uma chave AES-256 a partir de uma senha usando PBKDF2
    Retorna (chave, salt)
    """
    if salt is None:
        salt = get_random_bytes(16)  # Salt aleatório de 16 bytes

    # Derivar chave usando PBKDF2 (100000 iterações)
    chave = hashlib.pbkdf2_hmac('sha256', senha.encode(), salt, 100000, dklen=32)  # AES-256 (32 bytes)

    return chave, salt


def encriptar_aes(dados: str, chave_aes: bytes) -> tuple:
    """
    Encripta dados usando AES-256 em modo GCM (Galois/Counter Mode)
    Retorna (nonce, tag, ciphertext)
    """
    nonce = get_random_bytes(12)  # Nonce aleatório de 12 bytes para GCM
    cipher = AES.new(chave_aes, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(dados.encode())

    return nonce, tag, ciphertext


def decriptar_aes(nonce: bytes, tag: bytes, ciphertext: bytes, chave_aes: bytes) -> str:
    """
    Decripta dados usando AES-256 em modo GCM
    """
    cipher = AES.new(chave_aes, AES.MODE_GCM, nonce=nonce)
    dados = cipher.decrypt_and_verify(ciphertext, tag)

    return dados.decode()


def codificacao_hibrida_v32(texto: str, chave_vigenere: str, chave_xor: str, chave_hmac: str, chave_aes: str) -> str:
    """Versão 3.2 da codificação híbrida com AES-256 e HMAC"""
    # Fase 1: Aplicar Vigenère
    texto_vigenere = cifra_vigenere(texto, chave_vigenere, 'codificar')

    # Fase 2: Derivar chave AES da senha
    chave_aes_bytes, salt = derivar_chave_aes(chave_aes)

    # Fase 3: Encriptar com AES-256 GCM
    nonce, tag, ciphertext = encriptar_aes(texto_vigenere, chave_aes_bytes)

    # Fase 4: Combinar elementos para transporte
    elementos = {
        "s": base64.b64encode(salt).decode(),  # salt para derivação da chave
        "n": base64.b64encode(nonce).decode(),  # nonce do AES
        "t": base64.b64encode(tag).decode(),  # tag de autenticação do AES
        "c": base64.b64encode(ciphertext).decode()  # conteúdo cifrado
    }

    # Codificar os elementos em um JSON string e aplicar codificação avançada
    import json
    elementos_json = json.dumps(elementos)
    texto_avancado = codificacao_avancada(elementos_json, chave_xor)

    # Gerar HMAC para autenticação e verificação de integridade
    hmac_valor = gerar_hmac(texto_avancado, chave_hmac)

    # Formato final: texto_codificado.hmac
    return f"{texto_avancado}.{hmac_valor}"


def decodificacao_hibrida_v32(texto_codificado: str, chave_vigenere: str, chave_xor: str, chave_hmac: str,
                              chave_aes: str) -> str:
    """Versão 3.2 da decodificação híbrida com AES-256 e verificação HMAC"""
    try:
        # Separar o texto codificado do HMAC
        partes = texto_codificado.split('.')
        if len(partes) != 2:
            raise ValueError("Formato inválido: HMAC não encontrado")

        texto_avancado, hmac_recebido = partes

        # Verificar HMAC para garantir integridade
        if not verificar_hmac(texto_avancado, chave_hmac, hmac_recebido):
            raise ValueError("HMAC inválido: o conteúdo pode ter sido adulterado")

        # Decodificar com o método avançado para obter o JSON
        json_elementos = decodificacao_avancada(texto_avancado, chave_xor)

        # Extrair os elementos
        import json
        elementos = json.loads(json_elementos)

        # Decodificar de Base64
        salt = base64.b64decode(elementos["s"])
        nonce = base64.b64decode(elementos["n"])
        tag = base64.b64decode(elementos["t"])
        ciphertext = base64.b64decode(elementos["c"])

        # Derivar a chave AES a partir da senha e do salt
        chave_aes_bytes, _ = derivar_chave_aes(chave_aes, salt)

        # Decriptar com AES
        texto_vigenere = decriptar_aes(nonce, tag, ciphertext, chave_aes_bytes)

        # Decodificar Vigenère
        return cifra_vigenere(texto_vigenere, chave_vigenere, 'decodificar')

    except Exception as e:
        raise ValueError(f"Erro na decodificação: {str(e)}")


def selecionar_diretorio(titulo="Selecionar Diretório"):
    root = tk.Tk()
    root.withdraw()
    diretorio = filedialog.askdirectory(title=titulo)
    root.destroy()
    return diretorio


def selecionar_arquivos(titulo="Selecionar Arquivos",
                        tipos=(("Arquivos de texto", "*.txt"), ("Todos os arquivos", "*.*"))):
    root = tk.Tk()
    root.withdraw()
    arquivos = filedialog.askopenfilenames(title=titulo, filetypes=tipos)
    root.destroy()
    return list(arquivos)


def selecionar_diretorio_salvar(titulo="Salvar em"):
    root = tk.Tk()
    root.withdraw()
    diretorio = filedialog.askdirectory(title=titulo)
    root.destroy()
    return diretorio


def processa_arquivo_batch(arquivo, chave_vigenere, chave_xor, chave_hmac, chave_aes, modo, diretorio_saida):
    try:
        if not os.path.exists(diretorio_saida):
            os.makedirs(diretorio_saida)

        with open(arquivo, 'r', encoding='utf-8') as f:
            conteudo = f.read()

        nome_arquivo = os.path.basename(arquivo)
        extensao = '.encoded' if modo == 'codificar' else '.txt'
        arquivo_saida = os.path.join(diretorio_saida, nome_arquivo + extensao)

        if modo == 'codificar':
            resultado = codificacao_hibrida_v32(conteudo, chave_vigenere, chave_xor, chave_hmac, chave_aes)
        else:
            resultado = decodificacao_hibrida_v32(conteudo, chave_vigenere, chave_xor, chave_hmac, chave_aes)

        with open(arquivo_saida, 'w', encoding='utf-8') as f:
            f.write(resultado)

        return True, arquivo_saida
    except Exception as e:
        return False, str(e)


def obter_senha_segura(mensagem):
    """Solicita uma senha de forma segura e verifica sua força"""
    while True:
        # Usar getpass para entrada invisível da senha
        senha = getpass.getpass(mensagem)

        # Verificar força da senha
        if len(senha) < 12:
            print(f"{Fore.LIGHTRED_EX}Senha muito curta. Use pelo menos 12 caracteres.")
            continue

        tem_maiuscula = any(c.isupper() for c in senha)
        tem_minuscula = any(c.islower() for c in senha)
        tem_numero = any(c.isdigit() for c in senha)
        tem_especial = any(not c.isalnum() for c in senha)

        pontos = sum([tem_maiuscula, tem_minuscula, tem_numero, tem_especial])

        if pontos < 3:
            print(f"{Fore.LIGHTRED_EX}Senha fraca. Use letras maiúsculas, minúsculas, números e caracteres especiais.")
            continue

        return senha


def executar_modo_batch(modo):
    os.system('cls')
    print(BANNER)
    print(SEPARADOR)

    titulo = "CODIFICAÇÃO EM LOTE" if modo == 'codificar' else "DECODIFICAÇÃO EM LOTE"
    print(f"{Fore.LIGHTCYAN_EX}►► {titulo} (MODO HÍBRIDO V3.2) ◄◄\n")

    print(f"{Fore.LIGHTWHITE_EX}Selecione os arquivos para processamento...")
    arquivos = selecionar_arquivos(
        titulo=f"Selecionar arquivos para {modo}",
        tipos=[
            ("Arquivos de texto", "*.txt"),
            ("Arquivos codificados", "*.encoded"),
            ("Todos os arquivos", "*.*")
        ]
    )

    if not arquivos:
        print(f"{Fore.LIGHTRED_EX}Nenhum arquivo selecionado.")
        input(f"{Fore.LIGHTBLACK_EX}\nPressione Enter para continuar...")
        return

    print(f"{Fore.LIGHTGREEN_EX}Encontrados {len(arquivos)} arquivos para processar.")

    print(f"{Fore.LIGHTWHITE_EX}Selecione o diretório para salvar os resultados...")
    diretorio_saida = selecionar_diretorio_salvar(f"Selecionar diretório para salvar os arquivos {modo}dos")

    if not diretorio_saida:
        print(f"{Fore.LIGHTRED_EX}Nenhum diretório de destino selecionado.")
        input(f"{Fore.LIGHTBLACK_EX}\nPressione Enter para continuar...")
        return

    chave_vigenere = input(f"{Fore.LIGHTWHITE_EX}►► Digite a chave Vigenère: ")
    chave_xor = input(f"{Fore.LIGHTWHITE_EX}►► Digite a chave XOR: ")
    chave_hmac = input(f"{Fore.LIGHTWHITE_EX}►► Digite a chave HMAC (autenticação): ")
    chave_aes = obter_senha_segura(f"{Fore.LIGHTWHITE_EX}►► Digite a chave AES-256 (senha mestra): ")

    print(f"\n{Fore.LIGHTYELLOW_EX}Pronto para processar {len(arquivos)} arquivos. Confirma? (s/n): ", end="")
    if input().lower() != 's':
        print(f"{Fore.LIGHTRED_EX}Operação cancelada pelo usuário.")
        input(f"{Fore.LIGHTBLACK_EX}\nPressione Enter para continuar...")
        return

    print(f"\n{Fore.LIGHTWHITE_EX}Processando arquivos:")

    sucessos = 0
    falhas = 0
    arquivos_falhados = []
    tempo_inicio = time.time()

    for arquivo in tqdm(arquivos, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]'):
        sucesso, resultado = processa_arquivo_batch(
            arquivo, chave_vigenere, chave_xor, chave_hmac, chave_aes, modo, diretorio_saida
        )

        if sucesso:
            sucessos += 1
        else:
            falhas += 1
            arquivos_falhados.append((os.path.basename(arquivo), resultado))

    tempo_total = time.time() - tempo_inicio

    print(f"\n{Fore.LIGHTGREEN_EX}Operação concluída em {tempo_total:.2f} segundos!")
    print(f"{Fore.LIGHTGREEN_EX}Arquivos processados com sucesso: {sucessos}")

    if falhas > 0:
        print(f"{Fore.LIGHTRED_EX}Arquivos com falha: {falhas}")
        print(f"{Fore.LIGHTRED_EX}Detalhes das falhas:")
        for arquivo, erro in arquivos_falhados:
            print(f"{Fore.LIGHTRED_EX}- {arquivo}: {erro}")

    print(f"\n{Fore.LIGHTGREEN_EX}Resultados salvos em: {diretorio_saida}")
    input(f"{Fore.LIGHTBLACK_EX}\nPressione Enter para continuar...")


def mostrar_sobre():
    os.system('cls')
    print(BANNER)
    print(SEPARADOR)
    print(f"{Fore.LIGHTCYAN_EX}Sobre o Base69 v3.2 Pro\n")
    print(f"{Fore.LIGHTWHITE_EX}Base69 é uma ferramenta de codificação híbrida que combina múltiplas")
    print(f"{Fore.LIGHTWHITE_EX}técnicas de criptografia para oferecer segurança em camadas.")
    print("")
    print(f"{Fore.LIGHTYELLOW_EX}Camadas de segurança na versão 3.2:")
    print(f"{Fore.LIGHTWHITE_EX}1. Cifra de Vigenère - criptografia clássica")
    print(f"{Fore.LIGHTWHITE_EX}2. AES-256 em modo GCM - criptografia de nível militar")
    print(f"{Fore.LIGHTWHITE_EX}3. Derivação de chave PBKDF2 - proteção contra ataques de força bruta")
    print(f"{Fore.LIGHTWHITE_EX}4. Codificação avançada - ofuscação adicional")
    print(f"{Fore.LIGHTWHITE_EX}5. HMAC-SHA256 - verificação de integridade e autenticidade")
    print("")
    print(f"{Fore.LIGHTCYAN_EX}Segurança adicional:")
    print(f"{Fore.LIGHTWHITE_EX}• Salt único para cada arquivo")
    print(f"{Fore.LIGHTWHITE_EX}• Proteção contra adulteração via HMAC")
    print(f"{Fore.LIGHTWHITE_EX}• Verificação da força de senhas")
    print(f"{Fore.LIGHTWHITE_EX}• Modo batch para processamento seguro de múltiplos arquivos")
    print(SEPARADOR)
    input(f"{Fore.LIGHTBLACK_EX}\nPressione Enter para voltar ao menu principal...")


def mostrar_menu():
    os.system("cls")
    print(BANNER)
    print(SEPARADOR)
    print(f"{Fore.LIGHTWHITE_EX}1. Codificação Básica (Base64)")
    print(f"{Fore.LIGHTWHITE_EX}2. Decodificação Básica (Base64)")
    print(f"{Fore.LIGHTWHITE_EX}3. Recodificação em Base64")
    print(f"{Fore.LIGHTCYAN_EX}4. Codificação Híbrida V3.2 (AES-256 + Vigenère + HMAC)")
    print(f"{Fore.LIGHTCYAN_EX}5. Decodificação Híbrida V3.2 (AES-256 + Vigenère + HMAC)")
    print(f"{Fore.LIGHTMAGENTA_EX}6. Modo Batch - Codificação Híbrida V3.2")
    print(f"{Fore.LIGHTMAGENTA_EX}7. Modo Batch - Decodificação Híbrida V3.2")
    print(f"{Fore.LIGHTGREEN_EX}8. Sobre Base69 v3.2")
    print(f"{Fore.LIGHTRED_EX}0. Sair")
    print(SEPARADOR)


def obter_texto(mensagem: str) -> str:
    print(f"{Fore.LIGHTWHITE_EX}{mensagem} (digite um espaço e pressione Enter para finalizar):")
    linhas = []
    while True:
        linha = input()
        if linha == ' ':
            break
        linhas.append(linha)
    return '\n'.join(linhas)


def main():
    while True:
        mostrar_menu()
        escolha = input(f"\n{Fore.LIGHTWHITE_EX}►► Escolha uma opção (0-8): ")

        if escolha == '1':
            texto = obter_texto("Digite o texto para codificar")
            codificado = base64.b64encode(texto.encode()).decode()
            print(f"{Fore.LIGHTGREEN_EX}\nTexto codificado:\n{codificado}")
            if input(f"{Fore.LIGHTWHITE_EX}►► Copiar para área de transferência? (s/n): ").lower() == 's':
                pyperclip.copy(codificado)
            input(f"{Fore.LIGHTBLACK_EX}\nPressione Enter para continuar...")

        elif escolha == '2':
            texto = obter_texto("Digite o texto Base64 para decodificar")
            try:
                decodificado = base64.b64decode(texto.encode()).decode()
                print(f"{Fore.LIGHTGREEN_EX}\nTexto decodificado:\n{decodificado}")
                if input(f"{Fore.LIGHTWHITE_EX}►► Copiar? (s/n): ").lower() == 's':
                    pyperclip.copy(decodificado)
            except Exception as e:
                print(f"{Fore.LIGHTRED_EX}Erro: Texto Base64 inválido!")
            input(f"{Fore.LIGHTBLACK_EX}\nPressione Enter para continuar...")

        elif escolha == '3':
            texto = obter_texto("Digite o texto Base64 para recodificar")
            try:
                decodificado = base64.b64decode(texto.encode()).decode()
                recodificado = base64.b64encode(decodificado.encode()).decode()
                print(f"{Fore.LIGHTGREEN_EX}\nTexto recodificado:\n{recodificado}")
                if input(f"{Fore.LIGHTWHITE_EX}►► Copiar? (s/n): ").lower() == 's':
                    pyperclip.copy(recodificado)
            except Exception as e:
                print(f"{Fore.LIGHTRED_EX}Erro: Texto Base64 inválido!")
            input(f"{Fore.LIGHTBLACK_EX}\nPressione Enter para continuar...")

        elif escolha == '4':
            texto = obter_texto("Digite o texto para codificação híbrida V3.2")
            chave_v = input(f"{Fore.LIGHTWHITE_EX}►► Digite a chave Vigenère: ")
            chave_x = input(f"{Fore.LIGHTWHITE_EX}►► Digite a chave XOR: ")
            chave_h = input(f"{Fore.LIGHTWHITE_EX}►► Digite a chave HMAC (autenticação): ")
            chave_a = obter_senha_segura(f"{Fore.LIGHTWHITE_EX}►► Digite a chave AES-256 (senha mestra): ")
            try:
                codificado = codificacao_hibrida_v32(texto, chave_v, chave_x, chave_h, chave_a)
                print(f"{Fore.LIGHTGREEN_EX}\nTexto codificado (Híbrido V3.2):\n{codificado}")
                if input(f"{Fore.LIGHTWHITE_EX}►► Copiar? (s/n): ").lower() == 's':
                    pyperclip.copy(codificado)
            except Exception as e:
                print(f"{Fore.LIGHTRED_EX}Erro: {str(e)}")
            input(f"{Fore.LIGHTBLACK_EX}\nPressione Enter para continuar...")

        elif escolha == '5':
            texto = obter_texto("Digite o texto codificado (Híbrido V3.2)")
            chave_v = input(f"{Fore.LIGHTWHITE_EX}►► Digite a chave Vigenère: ")
            chave_x = input(f"{Fore.LIGHTWHITE_EX}►► Digite a chave XOR: ")
            chave_h = input(f"{Fore.LIGHTWHITE_EX}►► Digite a chave HMAC (autenticação): ")
            chave_a = getpass.getpass(f"{Fore.LIGHTWHITE_EX}►► Digite a chave AES-256 (senha mestra): ")
            try:
                decodificado = decodificacao_hibrida_v32(texto, chave_v, chave_x, chave_h, chave_a)
                print(f"{Fore.LIGHTGREEN_EX}\nTexto decodificado:\n{decodificado}")
                if input(f"{Fore.LIGHTWHITE_EX}►► Copiar? (s/n): ").lower() == 's':
                    pyperclip.copy(decodificado)
            except Exception as e:
                print(f"{Fore.LIGHTRED_EX}Erro: {str(e)}")
            input(f"{Fore.LIGHTBLACK_EX}\nPressione Enter para continuar...")

        elif escolha == '6':
            executar_modo_batch('codificar')

        elif escolha == '7':
            executar_modo_batch('decodificar')

        elif escolha == '8':
            mostrar_sobre()

        elif escolha == '0':
            print(f"\n{Fore.LIGHTCYAN_EX}Até logo!")
            break

        else:
            print(f"\n{Fore.LIGHTRED_EX}Opção inválida! Use números de 0 a 8.")
            input(f"{Fore.LIGHTBLACK_EX}\nPressione Enter para continuar...")


if __name__ == "__main__":
    main()