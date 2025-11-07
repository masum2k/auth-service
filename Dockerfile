# --- 1. Aşama: Build (Projenin .jar dosyasını oluşturma) ---
FROM eclipse-temurin:21-jdk-jammy as builder

WORKDIR /app

# Maven wrapper dosyalarını kopyala
COPY mvnw .
COPY .mvn .mvn

# Projenin bağımlılıklarını kopyala ve indir
COPY pom.xml .
RUN ./mvnw dependency:go-offline

# Tüm proje kaynak kodunu kopyala
COPY src src

# Projeyi build et (testleri atla)
RUN ./mvnw clean package -Dmaven.test.skip=true

# --- 2. Aşama: Run (Projenin son imajını oluşturma) ---
FROM eclipse-temurin:21-jre-jammy

WORKDIR /app

# Sadece 1. aşamada (builder) oluşturulan .jar dosyasını kopyala
# NOT: pom.xml'deki <artifactId> 'auth-service' ise, target/*.jar da çalışır.
COPY --from=builder /app/target/*.jar app.jar

# Uygulamanın 8082 portunu açtığını belirt
EXPOSE 8082

# Konteyner başladığında çalıştırılacak komut
ENTRYPOINT ["java", "-jar", "app.jar"]