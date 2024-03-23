# Cofre de Senhas Seguro

Este é um cofre de senhas projetado para gerar suas credenciais, armazenando as credenciais geradas usando criptografia AES IGE, Scrypt e um código OTP (One-Time Password). A proposta deste cofre é fornecer uma camada adicional de segurança conhecida como "honey encryption".

## Como Usar

Para utilizar o cofre de senhas, siga as instruções abaixo:

### Pré-requisitos

- Certifique-se de ter o Go instalado na sua máquina.
- Certifique-se de ter todas as dependências instaladas. Você pode instalá-las executando `go mod tidy`.

### Modos Disponíveis

Existem diferentes modos disponíveis para manipular o cofre de senhas:

#### Modo Gerar Cofre (Generate Vault)

Este modo é usado para criar um novo cofre.

```
$ vault -mode=generatevault -safe=false -password=SuaSenhaAqui
```

#### Modo Visualizar Cofre (View Vault)

Este modo é usado para visualizar o conteúdo do cofre.

```
$ vault -mode=viewvault -safe=false -password=SuaSenhaAqui
```

#### Modo Alterar Senha (Change Password)

Este modo é usado para alterar a senha do cofre.

```
$ vault -mode=changepass -safe=false -password=SuaSenhaAqui -newpassword=SuaNovaSenhaAqui -otp=000000
```

#### Modo Remover Senha (Remove Password)

Este modo é usado para remover uma senha específica do cofre.

```
$ vault -mode=removepass -safe=false -id=00000000-0000-0000-0000-000000000000
```

#### Modo Adicionar Senha (Add Password)

Este modo é usado para adicionar uma nova senha ao cofre.

```
$ vault -mode=addpass -safe=false -password=SuaSenhaAqui -url="http://exemplo.com" -user=admin -size=16 -pattern=2 -otp=000000
```

### Padrões Disponíveis

Ao adicionar uma senha, você precisa selecionar um padrão. Veja os padrões disponíveis:

- Pattern 0: [0-9]
- Pattern 1: [a-zA-Z]
- Pattern 2: [a-zA-Z0-9]
- Pattern 3: * (base91)

Escolha o padrão correspondente ao tipo de senha que deseja gerar.

## Aviso

Certifique-se de escolher senhas seguras e gerar OTPs de forma segura para garantir a máxima proteção dos seus dados.
