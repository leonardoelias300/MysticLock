import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
from reedsolo import RSCodec

BASE64_CHARS = list("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

RS_PARITY_BYTES = 32
rs = RSCodec(RS_PARITY_BYTES)
BLOCO_DADOS = 255 - RS_PARITY_BYTES  # 223 bytes de dados por bloco

def gerar_chave(seed, salt):
    seed_bytes = seed.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    chave = kdf.derive(seed_bytes)
    return base64.urlsafe_b64encode(chave)

def gerar_indices_permutacao(seed, tamanho):
    seed_bytes = seed.encode('utf-8')
    hash_obj = hashlib.sha256(seed_bytes)
    hash_bytes = hash_obj.digest()
    indices = list(range(tamanho))
    for i in range(tamanho):
        j = (hash_bytes[i % len(hash_bytes)] + i) % tamanho
        indices[i], indices[j] = indices[j], indices[i]
    return indices

def gerar_tabela_codificacao(seed):
    seed_bytes = seed.encode('utf-8')
    hash_obj = hashlib.sha256(seed_bytes + b"tabela")
    hash_bytes = hash_obj.digest()
    tabela = BASE64_CHARS.copy()
    for i in range(len(tabela)):
        j = (hash_bytes[i % len(hash_bytes)] + i) % len(tabela)
        tabela[i], tabela[j] = tabela[j], tabela[i]
    return tabela

def codificacao_personalizada(dados, seed):
    tabela = gerar_tabela_codificacao(seed)
    resultado = []
    for i in range(0, len(dados), 3):
        grupo = dados[i:i+3]
        bits = 0
        for j, b in enumerate(grupo):
            bits |= b << (16 - j * 8)
        num_chars = (len(grupo) * 8 + 5) // 6
        for j in range(num_chars):
            idx = (bits >> (18 - j * 6)) & 0x3F
            resultado.append(tabela[idx])
    return ''.join(resultado)

def decodificacao_personalizada(string, seed):
    tabela = gerar_tabela_codificacao(seed)
    inv_tabela = {c: i for i, c in enumerate(tabela)}
    num_bytes = (len(string) * 6) // 8
    dados = bytearray()
    for i in range(0, len(string), 4):
        grupo = string[i:i+4]
        bits = 0
        for j, c in enumerate(grupo):
            bits |= inv_tabela.get(c, 0) << (18 - j * 6)
        num_bytes_grupo = min(3, (len(grupo) * 6) // 8)
        for j in range(num_bytes_grupo):
            byte = (bits >> (16 - j * 8)) & 0xFF
            dados.append(byte)
    return bytes(dados)

def aplicar_ofuscacao(dados, seed):
    dados_bytes = list(dados)
    tamanho = len(dados_bytes)
    indices = gerar_indices_permutacao(seed, tamanho)
    resultado = [0] * tamanho
    for i, idx in enumerate(indices):
        resultado[idx] = dados_bytes[i]
    hash_obj = hashlib.sha256(seed.encode('utf-8') + b"xor")
    xor_bytes = hash_obj.digest()
    for i in range(tamanho):
        resultado[i] ^= xor_bytes[i % len(xor_bytes)]
    return bytes(resultado)

def reverter_ofuscacao(dados, seed):
    dados_bytes = list(dados)
    tamanho = len(dados_bytes)
    hash_obj = hashlib.sha256(seed.encode('utf-8') + b"xor")
    xor_bytes = hash_obj.digest()
    for i in range(tamanho):
        dados_bytes[i] ^= xor_bytes[i % len(xor_bytes)]
    indices = gerar_indices_permutacao(seed, tamanho)
    resultado = [0] * tamanho
    for i, idx in enumerate(indices):
        resultado[i] = dados_bytes[idx]
    return bytes(resultado)

def aplicar_reed_solomon(dados):
    tamanho_original = len(dados)
    tamanho_bytes = tamanho_original.to_bytes(4, 'big')
    dados_com_tamanho = tamanho_bytes + dados
    bloco_tamanho = BLOCO_DADOS  # 223 bytes
    resto = len(dados_com_tamanho) % bloco_tamanho
    if resto > 0:
        padding_len = bloco_tamanho - resto
        padding = os.urandom(padding_len)
        dados_com_tamanho += padding
    else:
        padding_len = 0
    blocos = [dados_com_tamanho[i:i+bloco_tamanho] for i in range(0, len(dados_com_tamanho), bloco_tamanho)]
    dados_corrigidos = bytearray()
    for bloco in blocos:
        bloco_corrigido = rs.encode(bloco)
        if len(bloco_corrigido) != 255:
            raise ValueError(f"Bloco codificado com tamanho inválido: {len(bloco_corrigido)}")
        dados_corrigidos.extend(bloco_corrigido)
    return bytes(dados_corrigidos)

def reverter_reed_solomon(dados):
    try:
        bloco_tamanho = 255
        blocos = [dados[i:i+bloco_tamanho] for i in range(0, len(dados), bloco_tamanho)]
        dados_originais = bytearray()
        for bloco in blocos:
            if len(bloco) != bloco_tamanho:
                raise ValueError(f"Bloco inválido: tamanho {len(bloco)} esperado {bloco_tamanho}")
            bloco_corrigido, _, _ = rs.decode(bloco)
            dados_originais.extend(bloco_corrigido[:BLOCO_DADOS])
        if len(dados_originais) < 4:
            raise ValueError("Dados insuficientes para extrair tamanho original")
        tamanho_original = int.from_bytes(dados_originais[:4], 'big')
        dados_sem_tamanho = dados_originais[4:]
        if len(dados_sem_tamanho) < tamanho_original:
            raise ValueError("Dados corrompidos: tamanho insuficiente após decodificação")
        dados_sem_padding = dados_sem_tamanho[:tamanho_original]
        return bytes(dados_sem_padding)
    except Exception as e:
        raise ValueError(f"Erro na correção Reed-Solomon: {str(e)}")

def criptografar_mensagem(mensagem, seed):
    salt = os.urandom(16)
    chave = gerar_chave(seed, salt)
    fernet = Fernet(chave)
    mensagem_bytes = mensagem.encode('utf-8')
    mensagem_criptografada = fernet.encrypt(mensagem_bytes)
    dados = salt + mensagem_criptografada
    dados_ofuscados = aplicar_ofuscacao(dados, seed)
    dados_com_ecc = aplicar_reed_solomon(dados_ofuscados)
    return codificacao_personalizada(dados_com_ecc, seed)

def descriptografar_mensagem(mensagem_criptografada, seed):
    try:
        dados_com_ecc = decodificacao_personalizada(mensagem_criptografada, seed)
        dados_ofuscados = reverter_reed_solomon(dados_com_ecc)
        dados = reverter_ofuscacao(dados_ofuscados, seed)
        if len(dados) < 16:
            raise ValueError("Dados ofuscados inválidos: tamanho insuficiente para conter o salt")
        salt = dados[:16]
        mensagem_criptografada = dados[16:]
        chave = gerar_chave(seed, salt)
        fernet = Fernet(chave)
        mensagem_descriptografada = fernet.decrypt(mensagem_criptografada).decode('utf-8')
        return mensagem_descriptografada
    except Exception as e:
        return f"Erro na descriptografia: {str(e)}"

def ler_arquivo(nome_arquivo):
    try:
        with open(nome_arquivo, 'r', encoding='utf-8') as arquivo:
            return arquivo.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Arquivo '{nome_arquivo}' não encontrado.")
    except Exception as e:
        raise Exception(f"Erro ao ler arquivo '{nome_arquivo}': {str(e)}")

def salvar_arquivo(nome_arquivo, conteudo):
    try:
        with open(nome_arquivo, 'w', encoding='utf-8') as arquivo:
            arquivo.write(conteudo)
        return True
    except Exception as e:
        print(f"Erro ao salvar arquivo '{nome_arquivo}': {str(e)}")
        return False

def processar_entrada(entrada, acao):
    if '.' in entrada and len(entrada.split('.')) >= 2:
        extensao = entrada.split('.')[-1].lower()
        
        if acao == 'C' and extensao == 'txt':
            try:
                conteudo = ler_arquivo(entrada)
                print(f"Arquivo '{entrada}' lido com sucesso. Conteúdo será criptografado.")
                return conteudo, entrada
            except Exception as e:
                print(f"Erro: {str(e)}")
                print("Tratando entrada como mensagem direta.")
                return entrada, None
                
        elif acao == 'D' and extensao == 'crypted':
            try:
                conteudo = ler_arquivo(entrada)
                print(f"Arquivo '{entrada}' lido com sucesso. Conteúdo será descriptografado.")
                return conteudo, entrada
            except Exception as e:
                print(f"Erro: {str(e)}")
                print("Tratando entrada como mensagem direta.")
                return entrada, None

    return entrada, None

def obter_nome_arquivo_saida(nome_arquivo_origem, acao):

    if nome_arquivo_origem:
        nome_base = '.'.join(nome_arquivo_origem.split('.')[:-1])
        if acao == 'C':
            return f"{nome_base}.crypted"
        else:  # acao == 'D'
            return f"{nome_base}.txt"
    return None

def main():
    print("=== Programa de Criptografia/Descriptografia com Ofuscação e Correção de Erros ===")
    seed = input("Digite a palavra ou frase que serve como seed: ")
    acao = input("Deseja (C)riptografar ou (D)escriptografar? [C/D]: ").strip().upper()
    
    if acao not in ['C', 'D']:
        print("Opção inválida! Escolha 'C' ou 'D'.")
        return
        
    if acao == 'C':
        entrada = input("Digite a mensagem ou arquivo (.txt) para criptografar: ")
        mensagem, arquivo_origem = processar_entrada(entrada, acao)
        
        mensagem_criptografada = criptografar_mensagem(mensagem, seed)

        if arquivo_origem:
            nome_arquivo_saida = obter_nome_arquivo_saida(arquivo_origem, acao)
            if salvar_arquivo(nome_arquivo_saida, mensagem_criptografada):
                print(f"Mensagem criptografada salva em: {nome_arquivo_saida}")
            else:
                print("Erro ao salvar arquivo. Exibindo resultado:")
                print("Mensagem criptografada:", mensagem_criptografada)
        else:
            print("Mensagem criptografada:", mensagem_criptografada)
            
    elif acao == 'D':
        entrada = input("Digite a mensagem ou arquivo (.crypted) para descriptografar: ")
        mensagem_criptografada, arquivo_origem = processar_entrada(entrada, acao)
        
        mensagem_descriptografada = descriptografar_mensagem(mensagem_criptografada, seed)

        if mensagem_descriptografada.startswith("Erro na descriptografia:"):
            print("Mensagem descriptografada:", mensagem_descriptografada)
        else:
            if arquivo_origem:
                nome_arquivo_saida = obter_nome_arquivo_saida(arquivo_origem, acao)
                if salvar_arquivo(nome_arquivo_saida, mensagem_descriptografada):
                    print(f"Mensagem descriptografada salva em: {nome_arquivo_saida}")
                else:
                    print("Erro ao salvar arquivo. Exibindo resultado:")
                    print("Mensagem descriptografada:", mensagem_descriptografada)
            else:
                print("Mensagem descriptografada:", mensagem_descriptografada)

if __name__ == "__main__":
    main()
