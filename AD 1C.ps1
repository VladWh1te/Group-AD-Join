# =====================================================================
# GUI для назначения групп безопасности 1С пользователю в Active Directory
# =====================================================================

# Подключение необходимых сборок .NET для работы с Windows Forms и графикой
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# =====================================================================
# ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
# =====================================================================
# Объявление глобальных переменных для хранения ссылок на элементы интерфейса и данные
$global:logBox = $null                    # Текстовое поле для отображения логов
$global:form = $null                      # Главная форма приложения
$global:userNameTextBox = $null           # Поле ввода для поиска пользователей
$global:groupList = @()                   # Массив чекбоксов с группами безопасности
$global:currentGroups = @()               # Текущие группы пользователя
$global:btnApply = $null                  # Кнопка применения изменений
$global:searchBox = $null                 # Поле поиска по группам
$global:searchTypeRadioLogin = $null      # Радиокнопка "Поиск по логину"
$global:searchTypeRadioName = $null       # Радиокнопка "Поиск по ФИО"
$global:allSecurityGroups = @()           # Все группы безопасности из AD
$global:originalGroups = @()              # Оригинальный список групп для сброса фильтра
$global:displayProperty = "DisplayName"   # Свойство отображаемого имени пользователя
$global:lastSelectedUser = $null          # Последний выбранный пользователь
$global:isResetting = $false              # Флаг для предотвращения рекурсии при сбросе

# =====================================================================
# ЦВЕТОВАЯ СХЕМА ИНТЕРФЕЙСА
# =====================================================================
# Определение цветовой палитры для统一ного стиля интерфейса
$colorPrimary = [System.Drawing.Color]::FromArgb(33, 150, 243)   # Основной синий цвет
$colorSecondary = [System.Drawing.Color]::FromArgb(26, 115, 232) # Вторичный темно-синий цвет
$colorBackground = [System.Drawing.Color]::FromArgb(245, 247, 250) # Фоновый светло-серый цвет
$colorPanelBg = [System.Drawing.Color]::White                    # Фон панелей
$colorText = [System.Drawing.Color]::FromArgb(50, 50, 50)        # Основной текст
$colorBorder = [System.Drawing.Color]::FromArgb(230, 230, 230)   # Цвет границ
$colorPlaceholder = [System.Drawing.Color]::FromArgb(150, 150, 150) # Цвет placeholder текста

# =====================================================================
# ФУНКЦИЯ: Сброс поля ввода
# Назначение: Очищает поле ввода и восстанавливает placeholder текст
# =====================================================================
function Reset-SearchBox {
    # Проверка флага для предотвращения рекурсии
    if ($global:isResetting) { return }
    
    # Установка флага для предотвращения рекурсии
    $global:isResetting = $true
    try {
        # Удаление обработчиков событий для предотвращения рекурсии
        $global:userNameTextBox.Remove_Enter($null)
        $global:userNameTextBox.Remove_Leave($null)
        
        # Очистка поля ввода
        $global:userNameTextBox.Text = ""
        $global:userNameTextBox.ForeColor = [System.Drawing.Color]::Black
        $global:userNameTextBox.Tag = $false
        
        # Восстановление обработчиков событий
        $global:userNameTextBox.Add_Enter({
            # При фокусировке убираем placeholder текст
            if ($global:userNameTextBox.Tag -eq $true) {
                $global:userNameTextBox.Text = ""
                $global:userNameTextBox.ForeColor = [System.Drawing.Color]::Black
                $global:userNameTextBox.Tag = $false
            }
        })
        
        $global:userNameTextBox.Add_Leave({
            # При потере фокуса показываем placeholder текст если поле пустое
            if ([string]::IsNullOrWhiteSpace($global:userNameTextBox.Text)) {
                if ($global:searchTypeRadioLogin.Checked) {
                    $global:userNameTextBox.Text = "Введите логин пользователя"
                } else {
                    $global:userNameTextBox.Text = "Введите фамилию пользователя"
                }
                $global:userNameTextBox.ForeColor = $colorPlaceholder
                $global:userNameTextBox.Tag = $true
            }
        })
    }
    finally {
        # Сброс флага рекурсии
        $global:isResetting = $false
    }
}

# =====================================================================
# ФУНКЦИЯ: Очистка состояния пользователя
# Назначение: Сбрасывает все данные о выбранном пользователе
# =====================================================================
function Clear-UserState {
    $global:currentGroups = @()           # Очистка текущих групп
    $global:btnApply.Enabled = $false     # Отключение кнопки применения
    $global:groupList = @()               # Очистка списка групп
    if ($scrollPanel) {
        $scrollPanel.Controls.Clear()     # Очистка панели с чекбоксами
    }
    $global:lastSelectedUser = $null      # Сброс выбранного пользователя
}

# =====================================================================
# ФУНКЦИЯ: Проверка прав администратора
# Назначение: Проверяет, запущен ли скрипт с правами администратора
# =====================================================================
function Test-IsAdmin {
    # Получение текущего пользователя и проверка принадлежности к группе администраторов
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# =====================================================================
# ФУНКЦИЯ: Логирование
# Назначение: Выводит сообщения в лог-панель или консоль
# =====================================================================
function Write-Log {
    param([string]$message)  # Параметр: сообщение для логирования
    
    # Форматирование времени и сообщения
    $timestamp = Get-Date -Format "HH:mm:ss"
    $logMessage = "[$timestamp] $message"
    
    # Проверка существования лог-панели и вывод сообщения
    if ($null -ne $global:logBox -and $global:logBox -is [System.Windows.Forms.TextBox]) {
        $global:logBox.AppendText("$logMessage`r`n")
        $global:logBox.ScrollToCaret()  # Прокрутка к последнему сообщению
    }
    else {
        # Если лог-панель не существует, выводим в консоль
        Write-Host $logMessage
    }
}

# =====================================================================
# ФУНКЦИЯ: Загрузка модуля ActiveDirectory
# Назначение: Проверяет и загружает модуль ActiveDirectory для работы с AD
# =====================================================================
function Load-ADModule {
    # Проверка прав администратора перед загрузкой модуля
    if (-not (Test-IsAdmin)) {
        Write-Log "ВНИМАНИЕ: Скрипт должен быть запущен от имени администратора."
        Write-Log "Для установки RSAT требуются права администратора."
        return $false
    }

    try {
        # Прямой импорт модуля ActiveDirectory
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log "Модуль ActiveDirectory успешно загружен."
        return $true
    }
    catch {
        # Обработка ошибок при загрузке модуля
        Write-Log ("Ошибка при импорте модуля: " + $_.Exception.Message)
        
        # Попытка загрузки модуля по известным путям
        $modulePaths = @(
            "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\ActiveDirectory",
            "C:\Program Files\WindowsPowerShell\v1.0\Modules\ActiveDirectory"
        )
        
        foreach ($path in $modulePaths) {
            if (Test-Path "$path\ActiveDirectory.psd1") {
                try {
                    Import-Module "$path\ActiveDirectory" -ErrorAction Stop
                    Write-Log ("Модуль загружен из: " + $path)
                    return $true
                }
                catch {
                    Write-Log ("Не удалось загрузить из " + $path + ": " + $_.Exception.Message)
                }
            }
        }
        
        # Проверка и установка RSAT для Windows 11
        $rsatCapability = Get-WindowsCapability -Online -ErrorAction SilentlyContinue | 
                          Where-Object { $_.Name -match 'Rsat\.ActiveDirectory\.DS-LDS\.Tools' }
        
        if ($rsatCapability) {
            if ($rsatCapability.State -eq "Installed") {
                Write-Log "RSAT установлен, но требуется перезапуск PowerShell от имени администратора"
            }
            else {
                Write-Log "RSAT не установлен. Для установки выполните в PowerShell (администратор):"
                Write-Log ("Add-WindowsCapability -Online -Name '" + $rsatCapability.Name + "'")
                Write-Log "После установки перезапустите PowerShell от имени администратора"
            }
        }
        else {
            Write-Log "Критическая ошибка: Не найден компонент RSAT для Active Directory"
            Write-Log "1. Убедитесь, что вы запустили PowerShell от имени администратора"
            Write-Log "2. Выполните установку вручную:"
            Write-Log "   Dism /Online /Add-Capability /CapabilityName:Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
            Write-Log "3. После установки перезапустите PowerShell от имени администратора"
        }
        return $false
    }
}

# =====================================================================
# ФУНКЦИЯ: Получение групп безопасности из AD
# Назначение: Ищет и возвращает все группы безопасности из OU "1С ibases.v8i"
# =====================================================================
function Get-SecurityGroups {
    try {
        # Поиск всех OU с именем "1С ibases.v8i" по всему домену
        $ous = Get-ADOrganizationalUnit -Filter "Name -eq '1С ibases.v8i'" -SearchScope Subtree -ErrorAction Stop
        $allGroups = @()
        Write-Log "Найдено $($ous.Count) OU с именем '1С ibases.v8i'"

        # Получение групп безопасности из каждой найденной OU
        foreach ($ou in $ous) {
            # Получение групп безопасности в этой OU
            $groups = Get-ADGroup -Filter "GroupCategory -eq 'Security'" -SearchBase $ou.DistinguishedName -SearchScope OneLevel -Properties Description
            $allGroups += $groups
            Write-Log "Найдено $($groups.Count) групп в OU: $($ou.DistinguishedName)"
        }

        # Сортировка и сохранение групп
        $global:allSecurityGroups = $allGroups | Sort-Object Name
        $global:originalGroups = $global:allSecurityGroups
        return $global:allSecurityGroups
    }
    catch {
        Write-Log ("Ошибка при получении групп: " + $_.Exception.Message)
        return @()
    }
}

# =====================================================================
# ФУНКЦИЯ: Фильтрация групп
# Назначение: Фильтрует отображаемые группы по тексту поиска
# =====================================================================
function Filter-Groups {
    param([string]$searchText)  # Параметр: текст для фильтрации
    
    # Очистка текста поиска и приведение к нижнему регистру
    $searchText = $searchText.Trim().ToLower()
    
    # Очистка текущего списка групп в интерфейсе
    if ($scrollPanel) {
        $scrollPanel.Controls.Clear()
    }
    
    # Фильтрация групп по тексту поиска
    $filteredGroups = if ([string]::IsNullOrWhiteSpace($searchText)) {
        $global:originalGroups  # Если пустой поиск, показываем все группы
    } else {
        $global:originalGroups | Where-Object {
            # Поиск по имени и описанию группы
            $groupName = $_.Name.ToLower()
            $groupDesc = if ($_.Description) { $_.Description.ToLower() } else { "" }
            $groupName.Contains($searchText) -or $groupDesc.Contains($searchText)
        }
    }
    
    # Перерисовка списка групп в интерфейсе
    if ($scrollPanel) {
        $yPosition = 5
        foreach ($group in $filteredGroups) {
            # Создание чекбокса для каждой группы
            $checkBox = New-Object System.Windows.Forms.CheckBox
            $checkBox.Text = if ($group.Description) { ($group.Name + " - " + $group.Description) } else { $group.Name }
            $checkBox.Tag = $group.Name  # Сохранение имени группы в теге
            $checkBox.Checked = $global:currentGroups.Name -contains $group.Name  # Установка состояния чекбокса
            $checkBox.Location = New-Object System.Drawing.Point(5, $yPosition)
            $checkBox.Size = New-Object System.Drawing.Size(720, 20)
            $checkBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $scrollPanel.Controls.Add($checkBox)
            $global:groupList += $checkBox
            $yPosition += 25
        }
    }
    
    Write-Log "Отображено $($filteredGroups.Count) групп (из $($global:originalGroups.Count))"
}

# =====================================================================
# ФУНКЦИЯ: Поиск пользователей по фамилии
# Назначение: Ищет пользователей в AD по фамилии
# =====================================================================
function Find-UsersByName {
    param([string]$lastName)  # Параметр: фамилия для поиска
    
    # Проверка наличия фамилии для поиска
    if (-not $lastName) {
        Write-Log "Ошибка: не указана фамилия для поиска."
        return $null
    }
    
    try {
        # Поиск пользователей по фамилии
        $users = Get-ADUser -Filter "Surname -like '$lastName*'" -Properties SamAccountName, $global:displayProperty | 
                 Select-Object SamAccountName, @{Name="FullName"; Expression={$_.$($global:displayProperty)}}
        
        # Проверка наличия найденных пользователей
        if ($users.Count -eq 0) {
            Write-Log "Пользователи с фамилией '$lastName' не найдены."
            return $null
        }
        
        return $users
    }
    catch {
        Write-Log ("Ошибка при поиске пользователей: " + $_.Exception.Message)
        return $null
    }
}

# =====================================================================
# ФУНКЦИЯ: Диалог выбора пользователя
# Назначение: Отображает диалоговое окно для выбора пользователя из списка
# =====================================================================
function Show-UserSelectionDialog {
    param([array]$users)  # Параметр: массив пользователей для выбора
    
    # Создание формы диалога выбора пользователя
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = "Выбор пользователя"
    $dialog.Size = New-Object System.Drawing.Size(500, 400)
    $dialog.StartPosition = "CenterScreen"
    $dialog.FormBorderStyle = "FixedDialog"
    $dialog.BackColor = $colorBackground
    
    # Создание заголовка диалога
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = "Найдено несколько пользователей:"
    $titleLabel.Location = New-Object System.Drawing.Point(20, 15)
    $titleLabel.Size = New-Object System.Drawing.Size(450, 25)
    $titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $titleLabel.ForeColor = $colorText
    $dialog.Controls.Add($titleLabel)
    
    # Создание списка пользователей
    $listView = New-Object System.Windows.Forms.ListView
    $listView.View = [System.Windows.Forms.View]::Details
    $listView.GridLines = $true
    $listView.FullRowSelect = $true
    $listView.Location = New-Object System.Drawing.Point(20, 50)
    $listView.Size = New-Object System.Drawing.Size(450, 250)
    $listView.BackColor = $colorPanelBg
    $listView.ForeColor = $colorText
    $listView.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    
    # Создание колонок списка
    $col1 = New-Object System.Windows.Forms.ColumnHeader
    $col1.Text = "Логин"
    $col1.Width = 150
    
    $col2 = New-Object System.Windows.Forms.ColumnHeader
    $col2.Text = "ФИО"
    $col2.Width = 300
    
    $listView.Columns.Add($col1) | Out-Null
    $listView.Columns.Add($col2) | Out-Null
    
    # Заполнение списка пользователями
    foreach ($user in $users) {
        $item = New-Object System.Windows.Forms.ListViewItem($user.SamAccountName)
        $item.SubItems.Add($user.FullName)
        $listView.Items.Add($item) | Out-Null
    }
    
    $dialog.Controls.Add($listView)
    
    # Создание кнопок диалога
    $btnSelect = New-Object System.Windows.Forms.Button
    $btnSelect.Text = "Выбрать"
    $btnSelect.Location = New-Object System.Drawing.Point(200, 320)
    $btnSelect.Size = New-Object System.Drawing.Size(100, 30)
    $btnSelect.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $btnSelect.BackColor = $colorPrimary
    $btnSelect.ForeColor = "White"
    $btnSelect.FlatStyle = "Flat"
    $btnSelect.FlatAppearance.BorderSize = 0
    $btnSelect.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $dialog.AcceptButton = $btnSelect
    
    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Отмена"
    $btnCancel.Location = New-Object System.Drawing.Point(310, 320)
    $btnCancel.Size = New-Object System.Drawing.Size(100, 30)
    $btnCancel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnCancel.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
    $btnCancel.ForeColor = $colorText
    $btnCancel.FlatStyle = "Flat"
    $btnCancel.FlatAppearance.BorderSize = 0
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    
    $dialog.Controls.Add($btnSelect)
    $dialog.Controls.Add($btnCancel)
    
    # Обработчик двойного клика по пользователю
    $listView.Add_DoubleClick({
        if ($listView.SelectedItems.Count -gt 0) {
            $dialog.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $dialog.Close()
        }
    })
    
    # Показ диалога и возврат результата
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        if ($listView.SelectedItems.Count -gt 0) {
            $selectedUser = $users[$listView.SelectedIndices[0]]
            $global:lastSelectedUser = $selectedUser
            return $selectedUser
        }
    } else {
        # При отмене сброс поля ввода
        $global:form.Invoke([Action]{
            Reset-SearchBox
        })
    }
    
    return $null
}

# =====================================================================
# ФУНКЦИЯ: Получение групп пользователя
# Назначение: Загружает и отображает группы выбранного пользователя
# =====================================================================
function Get-UserGroups {
    # Получение и очистка текста поиска
    $searchText = $userNameTextBox.Text.Trim()
    
    # Проверка на placeholder текст
    if ($userNameTextBox.Tag -eq $true -and ($searchText -eq "Введите логин пользователя" -or $searchText -eq "Введите фамилию пользователя")) {
        $searchText = ""
    }
    
    # Проверка наличия текста для поиска
    if (-not $searchText) {
        Write-Log "Ошибка: не указан текст для поиска."
        return
    }

    try {
        $selectedUser = $null
        
        # Определение типа поиска (по логину или по ФИО)
        if ($global:searchTypeRadioLogin.Checked) {
            # Поиск по логину
            $user = Get-ADUser -Identity $searchText -ErrorAction Stop -Properties SamAccountName, $global:displayProperty
            $selectedUser = @{
                SamAccountName = $user.SamAccountName
                FullName = $user.$($global:displayProperty)
            }
        }
        else {
            # Поиск по ФИО
            $users = Find-UsersByName $searchText
            
            if (-not $users) {
                return
            }
            
            # Если найден один пользователь - выбираем его, иначе показываем диалог выбора
            if ($users.Count -eq 1) {
                $selectedUser = $users[0]
                $global:lastSelectedUser = $selectedUser
            }
            else {
                $selectedUser = Show-UserSelectionDialog $users
                if (-not $selectedUser) {
                    return
                }
            }
        }
        
        # Проверка наличия выбранного пользователя
        if (-not $selectedUser) {
            Write-Log "Пользователь не найден."
            return
        }
        
        # Получение объекта пользователя из AD
        $user = Get-ADUser -Identity $selectedUser.SamAccountName -ErrorAction Stop
        
        # Проверка успешного получения пользователя
        if (-not $user) {
            Write-Log "Ошибка: пользователь не найден в Active Directory."
            return
        }
        
        # Получение текущих групп пользователя
        $global:currentGroups = Get-ADPrincipalGroupMembership $user | Where-Object { $_.GroupCategory -eq "Security" } | Select-Object Name

        # Очистка предыдущих элементов интерфейса
        $global:groupList = @()
        if ($scrollPanel) {
            $scrollPanel.Controls.Clear()
        }

        # Получение всех групп безопасности
        $allGroups = Get-SecurityGroups
        if ($allGroups.Count -eq 0) {
            Write-Log "Не найдено ни одной группы безопасности в домене"
            return
        }

        # Фильтрация групп по тексту поиска
        Filter-Groups $global:searchBox.Text

        # Включение кнопки применения изменений
        $global:btnApply.Enabled = $true
        Write-Log ("Группы загружены для пользователя: " + $selectedUser.SamAccountName)
        
        # Отображение информации о выбранном пользователе
        if (-not $global:searchTypeRadioLogin.Checked) {
            $fullName = $selectedUser.FullName
            Write-Log "Выбран пользователь: $fullName"
        }
        
        # Сохранение выбранного пользователя
        $global:lastSelectedUser = $selectedUser
        
    }
    catch {
        Write-Log ("Ошибка при получении данных пользователя: " + $_.Exception.Message)
    }
}

# =====================================================================
# ФУНКЦИЯ: Применение изменений
# Назначение: Применяет выбранные изменения групп пользователю
# =====================================================================
function Apply-Changes {
    # Использование сохраненного пользователя или текста из поля ввода
    $username = ""
    
    if ($global:lastSelectedUser) {
        $username = $global:lastSelectedUser.SamAccountName
    } else {
        $username = $userNameTextBox.Text.Trim()
        
        # Проверка на placeholder текст
        if ($userNameTextBox.Tag -eq $true -and ($username -eq "Введите логин пользователя" -or $username -eq "Введите фамилию пользователя")) {
            $username = ""
        }
    }
    
    # Проверка наличия логина пользователя
    if (-not $username) {
        Write-Log "Ошибка: не указан логин пользователя."
        return
    }

    try {
        # Получение объекта пользователя из AD
        $user = Get-ADUser -Identity $username -ErrorAction Stop

        # Проверка наличия пользователя
        if (-not $user) {
            Write-Log "Ошибка: пользователь не найден."
            return
        }

        # Получение списка всех групп из OU "1С ibases.v8i"
        $securityGroups = $global:allSecurityGroups | Select-Object -ExpandProperty Name
        
        # Получение только текущих групп пользователя из OU "1С ibases.v8i"
        $currentSecurityGroups = $global:currentGroups.Name | Where-Object { $_ -in $securityGroups }

        # Получение выбранных групп
        $selectedGroups = @()
        foreach ($cb in $global:groupList) {
            if ($cb.Checked -and $cb.Visible) {
                $selectedGroups += $cb.Tag
            }
        }

        # Определение групп для добавления/удаления
        $toAdd = $selectedGroups | Where-Object { $_ -notin $currentSecurityGroups }
        $toRemove = $currentSecurityGroups | Where-Object { $_ -notin $selectedGroups }

        # Логирование изменений
        $actions = @()
        if ($toAdd.Count -gt 0) {
            $actions += "Добавление: " + ($toAdd -join ', ')
        }
        if ($toRemove.Count -gt 0) {
            $actions += "Удаление: " + ($toRemove -join ', ')
        }

        # Проверка наличия изменений
        if ($actions.Count -eq 0) {
            Write-Log ("Нет изменений для пользователя " + $username + ".")
            return
        }

        Write-Log ("Применение изменений для пользователя: " + $username)
        Write-Log ("Действия: " + ($actions -join '; '))

        try {
            # Добавление групп пользователю
            if ($toAdd.Count -gt 0) {
                Add-ADPrincipalGroupMembership $user -MemberOf $toAdd -ErrorAction Stop
                Write-Log ("Добавлено: " + ($toAdd -join ', '))
            }
            # Удаление групп у пользователя
            if ($toRemove.Count -gt 0) {
                Remove-ADPrincipalGroupMembership $user -MemberOf $toRemove -Confirm:$false -ErrorAction Stop
                Write-Log ("Удалено: " + ($toRemove -join ', '))
            }

            Write-Log "Изменения применены успешно."
        }
        catch {
            Write-Log ("Ошибка при применении изменений: " + $_.Exception.Message)
        }
    }
    catch {
        Write-Log ("Ошибка при работе с пользователем " + $username + ": " + $_.Exception.Message)
    }
    finally {
        # Очистка состояния пользователя и сброс поля ввода
        Clear-UserState
        $global:form.Invoke([Action]{
            Reset-SearchBox
        })
    }
}

# =====================================================================
# ФУНКЦИЯ: Инициализация формы
# Назначение: Создает и настраивает графический интерфейс приложения
# =====================================================================
function Initialize-Form {
    # Создание главной формы приложения
    $global:form = New-Object System.Windows.Forms.Form
    $form.Text = "Active Directory - Управление группами безопасности 1С"
    $form.Size = New-Object System.Drawing.Size(850, 650)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.KeyPreview = $true  # Разрешение обработки клавиш
    $form.BackColor = $colorBackground
    $form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

    # =====================================================================
    # ПАНЕЛЬ ПОИСКА
    # =====================================================================
    # Создание панели поиска пользователей
    $searchPanel = New-Object System.Windows.Forms.Panel
    $searchPanel.Location = New-Object System.Drawing.Point(10, 10)
    $searchPanel.Size = New-Object System.Drawing.Size(820, 50)
    $searchPanel.BackColor = $colorPanelBg
    $searchPanel.BorderStyle = "FixedSingle"
    $form.Controls.Add($searchPanel)
    
    # Метка типа поиска
    $searchTypeLabel = New-Object System.Windows.Forms.Label
    $searchTypeLabel.Text = "Поиск по:"
    $searchTypeLabel.Location = New-Object System.Drawing.Point(10, 15)
    $searchTypeLabel.AutoSize = $true
    $searchPanel.Controls.Add($searchTypeLabel)
    
    # Панель для радиокнопок
    $radioPanel = New-Object System.Windows.Forms.Panel
    $radioPanel.Location = New-Object System.Drawing.Point(70, 12)
    $radioPanel.Size = New-Object System.Drawing.Size(250, 25)
    $radioPanel.BackColor = [System.Drawing.Color]::Transparent
    $searchPanel.Controls.Add($radioPanel)
    
    # Радиокнопка "Поиск по логину"
    $global:searchTypeRadioLogin = New-Object System.Windows.Forms.RadioButton
    $global:searchTypeRadioLogin.Text = "Логину"
    $global:searchTypeRadioLogin.Location = New-Object System.Drawing.Point(0, 0)
    $global:searchTypeRadioLogin.Size = New-Object System.Drawing.Size(80, 20)
    $global:searchTypeRadioLogin.Checked = $true
    $radioPanel.Controls.Add($global:searchTypeRadioLogin)
    
    # Радиокнопка "Поиск по ФИО"
    $global:searchTypeRadioName = New-Object System.Windows.Forms.RadioButton
    $global:searchTypeRadioName.Text = "ФИО"
    $global:searchTypeRadioName.Location = New-Object System.Drawing.Point(90, 0)
    $global:searchTypeRadioName.Size = New-Object System.Drawing.Size(80, 20)
    $radioPanel.Controls.Add($global:searchTypeRadioName)
    
    # Поле ввода для поиска пользователей
    $global:userNameTextBox = New-Object System.Windows.Forms.TextBox
    $global:userNameTextBox.Location = New-Object System.Drawing.Point(330, 12)
    $global:userNameTextBox.Size = New-Object System.Drawing.Size(200, 25)
    $global:userNameTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $global:userNameTextBox.TabIndex = 0
    $global:userNameTextBox.Text = "Введите логин пользователя"
    $global:userNameTextBox.ForeColor = $colorPlaceholder
    $global:userNameTextBox.Tag = $true

    # Обработчики событий для поля ввода
    $global:userNameTextBox.Add_Enter({
        # При фокусировке убираем placeholder текст
        if ($global:userNameTextBox.Tag -eq $true) {
            $global:userNameTextBox.Text = ""
            $global:userNameTextBox.ForeColor = [System.Drawing.Color]::Black
            $global:userNameTextBox.Tag = $false
        }
    })
    
    $global:userNameTextBox.Add_Leave({
        # При потере фокуса показываем placeholder текст если поле пустое
        if ([string]::IsNullOrWhiteSpace($global:userNameTextBox.Text)) {
            if ($global:searchTypeRadioLogin.Checked) {
                $global:userNameTextBox.Text = "Введите логин пользователя"
            } else {
                $global:userNameTextBox.Text = "Введите фамилию пользователя"
            }
            $global:userNameTextBox.ForeColor = $colorPlaceholder
            $global:userNameTextBox.Tag = $true
        }
    })

    $searchPanel.Controls.Add($global:userNameTextBox)

    # Кнопка "Проверить"
    $btnCheck = New-Object System.Windows.Forms.Button
    $btnCheck.Text = "Проверить"
    $btnCheck.Location = New-Object System.Drawing.Point(540, 10)
    $btnCheck.Size = New-Object System.Drawing.Size(100, 30)
    $btnCheck.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $btnCheck.BackColor = $colorPrimary
    $btnCheck.ForeColor = "White"
    $btnCheck.FlatStyle = "Flat"
    $btnCheck.FlatAppearance.BorderSize = 0
    $btnCheck.TabIndex = 1
    $btnCheck.Add_Click({
        Get-UserGroups
    })
    $searchPanel.Controls.Add($btnCheck)

    # Кнопка "Применить изменения"
    $global:btnApply = New-Object System.Windows.Forms.Button
    $global:btnApply.Text = "Применить изменения"
    $global:btnApply.Location = New-Object System.Drawing.Point(650, 10)
    $global:btnApply.Size = New-Object System.Drawing.Size(140, 30)
    $global:btnApply.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $global:btnApply.BackColor = $colorSecondary
    $global:btnApply.ForeColor = "White"
    $global:btnApply.FlatStyle = "Flat"
    $global:btnApply.FlatAppearance.BorderSize = 0
    $global:btnApply.TabIndex = 2
    $global:btnApply.Enabled = $false
    $global:btnApply.Add_Click({
        Apply-Changes
    })
    $searchPanel.Controls.Add($global:btnApply)

    # =====================================================================
    # ГРУППА СПИСКА ГРУПП
    # =====================================================================
    # Создание группы для отображения групп безопасности
    $groupBox = New-Object System.Windows.Forms.GroupBox
    $groupBox.Text = "Группы безопасности 1С (отметьте нужные)"
    $groupBox.Location = New-Object System.Drawing.Point(10, 70)
    $groupBox.Size = New-Object System.Drawing.Size(820, 400)
    $groupBox.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $groupBox.ForeColor = $colorPrimary
    $form.Controls.Add($groupBox)

    # Метка поиска групп
    $searchLabel = New-Object System.Windows.Forms.Label
    $searchLabel.Text = "Поиск групп:"
    $searchLabel.Location = New-Object System.Drawing.Point(10, 25)
    $searchLabel.AutoSize = $true
    $searchLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $groupBox.Controls.Add($searchLabel)

    # Поле ввода для поиска групп
    $global:searchBox = New-Object System.Windows.Forms.TextBox
    $global:searchBox.Location = New-Object System.Drawing.Point(90, 22)
    $global:searchBox.Size = New-Object System.Drawing.Size(300, 25)
    $global:searchBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $global:searchBox.TabIndex = 3
    $global:searchBox.Add_TextChanged({
        Filter-Groups $global:searchBox.Text
    })
    $groupBox.Controls.Add($global:searchBox)
    
    # Кнопка сброса поиска групп
    $btnClearSearch = New-Object System.Windows.Forms.Button
    $btnClearSearch.Text = "×"
    $btnClearSearch.Location = New-Object System.Drawing.Point(395, 22)
    $btnClearSearch.Size = New-Object System.Drawing.Size(25, 25)
    $btnClearSearch.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $btnClearSearch.FlatStyle = "Flat"
    $btnClearSearch.FlatAppearance.BorderSize = 0
    $btnClearSearch.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
    $btnClearSearch.Add_Click({
        $global:searchBox.Text = ""
        Filter-Groups ""
    })
    $groupBox.Controls.Add($btnClearSearch)

    # Панель с прокруткой для списка групп
    $global:groupList = @()
    $scrollPanel = New-Object System.Windows.Forms.Panel
    $scrollPanel.Location = New-Object System.Drawing.Point(10, 55)
    $scrollPanel.Size = New-Object System.Drawing.Size(800, 335)
    $scrollPanel.BackColor = $colorPanelBg
    $scrollPanel.BorderStyle = "FixedSingle"
    $scrollPanel.AutoScroll = $true
    $groupBox.Controls.Add($scrollPanel)

    # =====================================================================
    # ПАНЕЛЬ ЛОГОВ
    # =====================================================================
    # Метка журнала операций
    $logLabel = New-Object System.Windows.Forms.Label
    $logLabel.Text = "Журнал операций:"
    $logLabel.Location = New-Object System.Drawing.Point(10, 480)
    $logLabel.AutoSize = $true
    $logLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $logLabel.ForeColor = $colorPrimary
    $form.Controls.Add($logLabel)
    
    # Текстовое поле для отображения логов
    $global:logBox = New-Object System.Windows.Forms.TextBox
    $logBox.Multiline = $true
    $logBox.ReadOnly = $true
    $logBox.ScrollBars = "Vertical"
    $logBox.BackColor = [System.Drawing.Color]::FromArgb(248, 249, 252)
    $logBox.Location = New-Object System.Drawing.Point(10, 505)
    $logBox.Size = New-Object System.Drawing.Size(820, 100)
    $logBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    $logBox.BorderStyle = "FixedSingle"
    $form.Controls.Add($logBox)
    
    # =====================================================================
    # ИНФОРМАЦИОННАЯ ПАНЕЛЬ
    # =====================================================================
    # Информационная панель с подсказкой
    $infoPanel = New-Object System.Windows.Forms.Panel
    $infoPanel.Location = New-Object System.Drawing.Point(10, 610)
    $infoPanel.Size = New-Object System.Drawing.Size(820, 25)
    $infoPanel.BackColor = [System.Drawing.Color]::FromArgb(240, 245, 255)
    $infoPanel.BorderStyle = "None"
    $form.Controls.Add($infoPanel)
    
    $infoLabel = New-Object System.Windows.Forms.Label
    $infoLabel.Text = "Подсказка: Для поиска по ФИО введите фамилию и выберите пользователя из списка"
    $infoLabel.Location = New-Object System.Drawing.Point(10, 3)
    $infoLabel.AutoSize = $true
    $infoLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $infoLabel.ForeColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
    $infoPanel.Controls.Add($infoLabel)

    # =====================================================================
    # ОБРАБОТЧИКИ СОБЫТИЙ ФОРМЫ
    # =====================================================================
    # Обработчик закрытия формы
    $form.Add_FormClosing({
        if ($form.DialogResult -ne [System.Windows.Forms.DialogResult]::OK) {
            Write-Log "Скрипт завершен пользователем."
        }
    })

    # Обработчик нажатия клавиши Enter
    $form.Add_KeyUp({
        if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            if ($userNameTextBox.Focused) {
                $btnCheck.PerformClick()  # При фокусе на поле ввода - проверка
            }
            elseif ($global:btnApply.Enabled) {
                $global:btnApply.PerformClick()  # При доступной кнопке применения - применение
            }
        }
    })

    # Показ формы
    $form.ShowDialog()
}

# =====================================================================
# ГЛАВНЫЙ БЛОК ВЫПОЛНЕНИЯ
# Назначение: Точка входа в приложение, запуск основной логики
# =====================================================================
try {
    # Вывод информации о проверке окружения
    Write-Host "Проверка окружения..."
    
    # Проверка подключения к домену
    $domain = (Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue).Domain
    if (-not $domain -or $domain -eq "WORKGROUP") {
        Write-Host "Внимание: Компьютер не присоединен к домену!"
        Write-Host "Для работы с Active Directory требуется подключение к доменной сети."
    }
    else {
        Write-Host "Подключено к домену: $domain"
    }

    # Проверка прав администратора
    if (-not (Test-IsAdmin)) {
        Write-Host "ВНИМАНИЕ: Скрипт запущен без прав администратора!"
        Write-Host "Для установки RSAT требуются права администратора."
    }

    # Загрузка модуля ActiveDirectory и запуск формы
    if (Load-ADModule) {
        Write-Host "Запуск графического интерфейса..."
        Initialize-Form
    }
    else {
        Write-Host "КРИТИЧЕСКАЯ ОШИБКА: Не удалось загрузить модуль ActiveDirectory."
        
        # Создание формы с ошибкой
        $errorForm = New-Object System.Windows.Forms.Form
        $errorForm.Text = "Ошибка загрузки модуля ActiveDirectory"
        $errorForm.Size = New-Object System.Drawing.Size(600, 300)
        $errorForm.StartPosition = "CenterScreen"
        $errorForm.FormBorderStyle = "FixedDialog"
        $errorForm.MinimizeBox = $false
        $errorForm.MaximizeBox = $false
        $errorForm.BackColor = $colorBackground

        $errorLabel = New-Object System.Windows.Forms.Label
        $errorLabel.Text = @"
Не удалось загрузить модуль ActiveDirectory.

Порядок действий для Windows 11:

1. Запустите PowerShell от имени администратора
2. Выполните команду установки:
   Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
3. Перезапустите PowerShell
4. Запустите скрипт снова

Если ошибка сохраняется:
- Убедитесь, что компьютер подключен к доменной сети
- Проверьте наличие прав администратора домена
- Обратитесь к системному администратору
"@
        $errorLabel.Location = New-Object System.Drawing.Point(15, 15)
        $errorLabel.Size = New-Object System.Drawing.Size(570, 220)
        $errorLabel.TextAlign = "MiddleLeft"
        $errorLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $errorForm.Controls.Add($errorLabel)
        
        $btnOK = New-Object System.Windows.Forms.Button
        $btnOK.Text = "Закрыть"
        $btnOK.Location = New-Object System.Drawing.Point(250, 240)
        $btnOK.Size = New-Object System.Drawing.Size(100, 25)
        $btnOK.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
        $btnOK.BackColor = $colorPrimary
        $btnOK.ForeColor = "White"
        $btnOK.FlatStyle = "Flat"
        $btnOK.FlatAppearance.BorderSize = 0
        $btnOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $errorForm.Controls.Add($btnOK)
        
        $errorForm.AcceptButton = $btnOK
        $errorForm.ShowDialog() | Out-Null
    }
}
catch {
    # Обработка критических ошибок
    $errorMessage = $_.Exception.Message
    Write-Host "Критическая ошибка: $errorMessage" -ForegroundColor Red
    
    # Попытка показать сообщение об ошибке через Windows Forms
    try {
        [System.Windows.Forms.MessageBox]::Show("Критическая ошибка: $errorMessage", "Ошибка", "OK", "Error")
    }
    catch {
        Write-Host "Windows Forms недоступен: $($_.Exception.Message)"
    }
}