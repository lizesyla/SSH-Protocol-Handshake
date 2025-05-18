Ky projekt përfshin një implementim të thjeshtë të një sistemi SSH Client-Server në Java, që përdor:
-Protokollin Diffie-Hellman për shkëmbimin e çelësave
-Nënshkrimin dixhital (RSA) për verifikimin e serverit
-Autentikimin me emër përdoruesi dhe fjalëkalim

Përmbajtja
-SSHClient.java - Klienti që lidhet me serverin, verifikon identitetin e tij dhe dërgon kredencialet.
-SSHServer.java - Serveri që pret lidhje, gjeneron çelësa DH dhe RSA dhe verifikon klientin.

Si funksionon?
Serveri nis një socket TCP dhe gjeneron:
-një çift çelësash RSA për nënshkrimin dixhital
-një çift çelësash Diffie-Hellman për shkëmbimin e çelësave
Serveri:
-Dërgon çelësin publik DH të nënshkruar me çelësin privat RSA
-Dërgon çelësin publik RSA
Klienti:
-Verifikon nënshkrimin e çelësit publik DH duke përdorur çelësin publik RSA të serverit
-Nëse verifikimi dështon, ndërpret lidhjen
-Nëse verifikimi është i suksesshëm, dërgon çelësin publik të vet DH
-Të dy palët krijojnë një shared secret duke përdorur algoritmin Diffie-Hellman
-Klienti dërgon emrin e përdoruesit dhe fjalëkalimin, të cilat serveri i verifikon

Si të ekzekutohet?
Si të ekzekutohet?
1. Kompilimi
javac SSHServer.java SSHClient.java
2. Nisë serverin
java SSHServer --port 2222 --user admin --pass admin123
Argumentet opsionale:
--port <nr_porti> – Porti ku do të dëgjojë serveri (default: 2222)
--rsa-keysize <madhësia> – Madhësia e çelësit RSA (default: 2048)
--user <përdoruesi> – Emri i përdoruesit për autentikim
--pass <fjalëkalimi> – Fjalëkalimi për autentikim
--dh-p <hex> – Parametri P i DH
--dh-g <g> – Parametri G i DH
3. Nisë klientin
java SSHClient localhost 2222 admin admin123
Argumentet janë:
Adresa e serverit (default: localhost)
Porti (default: 2222)
Emri i përdoruesit (default: admin)
Fjalëkalimi (default: admin123)

Kërkesat
Java 8+
Nuk përdoren biblioteka të jashtme - vetëm java.security, javax.crypto dhe java.net

Autorët
Projekti u realizua si pjesë e një detyre për lëndën Siguria e të dhënave.
