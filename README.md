Запускаем скрипт (Run with PowerShell runme.ps1) локально на сервере.

Соглашаемся на запуск столь опасного ПО в PowerShell, а также не менее опасного Python.

Все, опасности позади, теперь:

1. Добавляем роли
2. Создаем пул + сайт
3. Берем архив с гитхаба и заливаем в inetpub/wwwroot
4. Устанавливаем права
5. Проверяем приложение на http://localhost:8080
6. Если все хорошо - Братишка отправляет в slack свое "фирменное"
7. В корне скрипта создается log с подробностями о происходящем

Есть 2 момента для удачного завершения:

1. Конфиг приложения имеет невалидную вестч system.web. , нужно system.web, точка портит жизнь
2. Мной было подвергнуто пыткам несколько .Net разработчиков, в итоге покойные сознались что compilation targetFramework="4.5.2"
httpRuntime targetFramework="4.5.2" обычно достаточно версии мажор+минор (4.5), что также требуется исправить в конфиге.
После вышеописанных корректировок скрипт проходит.https://github.com/Ninjamannn/deploy_script.git
	

