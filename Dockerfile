# --- 1. Aşama: Build (Projenin .jar dosyasını oluşturma) ---
FROM eclipse-temurin:21-jdk-jammy as builder

WORKDIR /app

# Sadece bağımlılık dosyalarını kopyala
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .

# Tüm kaynak kodu kopyala
COPY src src

# 'go-offline' ADIMINI KALDIRDIK.
# 'package' zaten gerekirse bağımlılıkları indirecek
# ve testleri atlayacak.
RUN ./mvnw clean package -Dmaven.test.skip=true

# --- 2. Aşama: Run (Projenin son imajını oluşturma) ---
FROM eclipse-temurin:21-jre-jammy

WORKDIR /app

# Sadece 1. aşamada (builder) oluşturulan .jar dosyasını kopyala
COPY --from=builder /app/target/*.jar app.jar

# (EXPOSE portunu her servisin kendi portuyla değiştir,
#  örn: api-gateway için 9000, auth-service için 8082 vb.)
EXPOSE 9000

ENTRYPOINT ["java", "-jar", "app.jar"]