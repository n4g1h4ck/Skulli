<img src='./skulli_small.png' width="200">

# SKULLi: Herramienta Avanzada para Inyección SQL

SKULLi es una herramienta de inyección SQL **robusta y eficiente**, diseñada para **profesionales de la ciberseguridad** y entusiastas del hacking ético. Su propósito principal es facilitar la identificación y explotación de vulnerabilidades de inyección SQL a través de diversos métodos, permitiendo una evaluación exhaustiva de la seguridad de bases de datos.

Esta herramienta se distingue por su **simplicidad de uso**, sin comprometer la profundidad de sus capacidades. SKULLi soporta múltiples tipos de inyección SQL, incluyendo:

-   **Inyecciones basadas en booleanos:** Determinación de la existencia de datos a través de respuestas verdaderas o falsas.
    
-   **Inyecciones basadas en tiempo:** Extracción de información mediante el análisis de retardos en las respuestas del servidor.
    
-   **Inyecciones basadas en errores:** Obtención de datos a partir de mensajes de error generados por la base de datos.
    
-   Entre otros métodos avanzados.
    

SKULLi ofrece funcionalidades versátiles que **optimizan el proceso de evaluación de vulnerabilidades**:

-   **Modo de inyección automática:** Permite la ejecución de pruebas sin la necesidad de configurar opciones adicionales, agilizando el proceso de detección.
    
-   **Exportación de datos:** Facilita la extracción de toda la información obtenida en un archivo de texto plano (`.txt`) para su posterior análisis y documentación.
    
-   **Extracción recursiva de información:** Posee la capacidad de navegar y extraer datos de múltiples bases de datos conectadas, permitiendo una exploración profunda y exhaustiva del entorno comprometido.
    

SKULLi es una **solución práctica y eficaz** para la auditoría de seguridad de sistemas, brindando las capacidades necesarias para identificar y mitigar riesgos asociados a la inyección SQL en entornos controlados y éticos.

----------

## Uso

La herramienta se ejecuta a través del archivo `start.py`, requiriendo un archivo JSON de configuración como argumento principal.

```bash
python3 start.py <json_file>
```

### Parámetros Opcionales

-   `-a`, `--automatic`: Activa el modo automático de inyección, obviando la necesidad de interacción manual para la selección de opciones.
    
-   `-l`, `--log <nombre_del_archivo>`: Permite guardar todos los datos extraídos durante la ejecución en un archivo de texto especificado.
    
-   `-r`, `--recursive`: Habilita el modo recursivo, permitiendo a SKULLi aplicar inyecciones en bases de datos secundarias descubiertas, facilitando la extracción de información de forma interconectada.