--[[
    Kavo UI Library - Material 3 Refactor

    This version aims to implement Material Design 3 principles
    and a more utility-driven styling approach.
]]

local Kavo = {}
Kavo.Version = "3.0.0-M3"

-- Roblox Services
local TweenService = game:GetService("TweenService")
local UserInputService = game:GetService("UserInputService")
local RunService = game:GetService("RunService")
local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")
local CoreGui = game:GetService("CoreGui")

-- Forward Declarations
local MaterialTheme
local Typography
local Sizing
local Elevation
local StyleUtils
local RippleEffectUtil

-- ##################################################################################
-- MATERIAL THEME DEFINITION (Colors, Typography, Sizing, Elevation)
-- ##################################################################################

MaterialTheme = {
    CurrentScheme = {}, -- Will hold the active color scheme
    Schemes = {},    -- Will store different color schemes (e.g., Light, Dark)

    -- Default Font (Roblox has limited font choices)
    DefaultFont = Enum.Font.Gotham, -- Or Enum.Font.SourceSans for a more Material feel

    -- Function to apply a surface tint (a common Material 3 effect for elevation)
    applySurfaceTint = function(element, color, elevationLevel)
        if not element or not color then return end
        local tintIntensity = {0, 0.05, 0.08, 0.11, 0.12, 0.14} -- Opacity levels for elevation 0-5
        local level = math.max(1, math.min(elevationLevel + 1, #tintIntensity)) -- elevationLevel 0-5

        local tintOverlay = element:FindFirstChild("M3SurfaceTint")
        if not tintOverlay then
            tintOverlay = Instance.new("Frame")
            tintOverlay.Name = "M3SurfaceTint"
            tintOverlay.Size = UDim2.new(1, 0, 1, 0)
            tintOverlay.ZIndex = element.ZIndex + 1 -- Ensure it's above the main background
            tintOverlay.BorderSizePixel = 0
            tintOverlay.Parent = element
        end
        tintOverlay.BackgroundColor3 = color
        tintOverlay.BackgroundTransparency = 1 - tintIntensity[level]
    end,

    -- Function to get a color from the current scheme
    getColor = function(colorName)
        return MaterialTheme.CurrentScheme[colorName] or Color3.fromRGB(255, 0, 255) -- Magenta for missing colors
    end,

    -- Function to set the active theme
    setTheme = function(themeName)
        if MaterialTheme.Schemes[themeName] then
            MaterialTheme.CurrentScheme = MaterialTheme.Schemes[themeName]
            -- TODO: Add event to notify all components to update their colors
            if Kavo.ActiveLibInstance and Kavo.ActiveLibInstance.UpdateTheme then
                Kavo.ActiveLibInstance:UpdateTheme()
            end
        else
            warn("Kavo M3: Theme '" .. themeName .. "' not found.")
        end
    end
}

Typography = {
    Styles = {
        DisplayLarge = { Font = MaterialTheme.DefaultFont, Weight = Enum.FontWeight.Bold, Size = 57, Tracking = -0.25 },
        DisplayMedium = { Font = MaterialTheme.DefaultFont, Weight = Enum.FontWeight.Bold, Size = 45, Tracking = 0 },
        DisplaySmall = { Font = MaterialTheme.DefaultFont, Weight = Enum.FontWeight.Bold, Size = 36, Tracking = 0 },

        HeadlineLarge = { Font = MaterialTheme.DefaultFont, Weight = Enum.FontWeight.SemiBold, Size = 32, Tracking = 0 },
        HeadlineMedium = { Font = MaterialTheme.DefaultFont, Weight = Enum.FontWeight.SemiBold, Size = 28, Tracking = 0 },
        HeadlineSmall = { Font = MaterialTheme.DefaultFont, Weight = Enum.FontWeight.SemiBold, Size = 24, Tracking = 0 },

        TitleLarge = { Font = MaterialTheme.DefaultFont, Weight = Enum.FontWeight.Medium, Size = 22, Tracking = 0 },
        TitleMedium = { Font = MaterialTheme.DefaultFont, Weight = Enum.FontWeight.Medium, Size = 16, Tracking = 0.15 },
        TitleSmall = { Font = MaterialTheme.DefaultFont, Weight = Enum.FontWeight.Medium, Size = 14, Tracking = 0.1 },

        LabelLarge = { Font = MaterialTheme.DefaultFont, Weight = Enum.FontWeight.Medium, Size = 14, Tracking = 0.1 },
        LabelMedium = { Font = MaterialTheme.DefaultFont, Weight = Enum.FontWeight.Medium, Size = 12, Tracking = 0.5 },
        LabelSmall = { Font = MaterialTheme.DefaultFont, Weight = Enum.FontWeight.Medium, Size = 11, Tracking = 0.5 },

        BodyLarge = { Font = MaterialTheme.DefaultFont, Weight = Enum.FontWeight.Regular, Size = 16, Tracking = 0.5 },
        BodyMedium = { Font = MaterialTheme.DefaultFont, Weight = Enum.FontWeight.Regular, Size = 14, Tracking = 0.25 },
        BodySmall = { Font = MaterialTheme.DefaultFont, Weight = Enum.FontWeight.Regular, Size = 12, Tracking = 0.4 },
    },

    applyStyle = function(textLabel, styleNameOrStyle)
        local style
        if type(styleNameOrStyle) == "string" then
            style = Typography.Styles[styleNameOrStyle]
        elseif type(styleNameOrStyle) == "table" then
            style = styleNameOrStyle
        end

        if style then
            textLabel.Font = style.Font
            textLabel.TextSize = style.Size
            if textLabel:IsA("TextLabel") or textLabel:IsA("TextButton") or textLabel:IsA("TextBox") then
                 -- Roblox doesn't have direct FontWeight for all fonts, Gotham is one of the few.
                pcall(function() textLabel.FontFace = Font.new(textLabel.FontFace.Family, style.Weight) end)
                -- Tracking (LetterSpacing) can be simulated with RichText or not at all.
                -- For simplicity, direct tracking is omitted here.
            end
        else
            warn("Kavo M3 Typography: Style '" .. tostring(styleNameOrStyle) .. "' not found.")
        end
    end
}

Sizing = {
    Padding = {
        None = UDim.new(0, 0),
        ExtraSmall = UDim.new(0, 4),
        Small = UDim.new(0, 8),
        Medium = UDim.new(0, 12), -- Common for text fields, buttons
        Large = UDim.new(0, 16),
        ExtraLarge = UDim.new(0, 24),
    },
    CornerRadius = {
        None = UDim.new(0, 0),
        ExtraSmall = UDim.new(0, 4),
        Small = UDim.new(0, 8),
        Medium = UDim.new(0, 12),
        Large = UDim.new(0, 16), -- Cards
        ExtraLarge = UDim.new(0, 28), -- FABs, Dialogs
        Full = UDim.new(1, 0) -- For circular elements if parent is square
    },
    ElementHeight = { -- Based on Material 3 guidelines
        CompactButton = 32,
        Button = 40,
        ExtendedFab = 56,
        TextField = 56,
        ListItem = 48,
        ListItemTwoLine = 64,
        ListItemThreeLine = 88,
    }
}

Elevation = {
    Levels = {0, 1, 2, 3, 4, 5}, -- M3 typically defines levels 0 through 5
    -- Shadow properties (approximations for Roblox)
    -- Format: {AmbientColor, AmbientTransparency, KeyColor, KeyTransparency, KeyOffsetY, KeyBlur (via multiple frames)}
    -- This is complex to do well in Roblox. A simpler approach is using UIStroke or a single drop shadow frame.
    -- For this refactor, we'll primarily use SurfaceTints and subtle borders.
    -- True shadows can be added with more complex frame layering or UIStroke.

    applyShadow = function(element, level)
        level = math.clamp(level, 0, #Elevation.Levels -1)
        
        local shadow = element:FindFirstChild("M3Shadow") or Instance.new("Frame")
        shadow.Name = "M3Shadow"
        shadow.Parent = element
        shadow.ZIndex = element.ZIndex -1 -- Behind the element
        shadow.Size = UDim2.new(1,0,1,0)
        shadow.Position = UDim2.new(0,0,0,0)
        shadow.BackgroundTransparency = 1 -- Default to no shadow for level 0

        local stroke = element:FindFirstChild("M3ShadowStroke") or Instance.new("UIStroke")
        stroke.Name = "M3ShadowStroke"
        stroke.Parent = element
        stroke.ApplyStrokeMode = Enum.ApplyStrokeMode.Border
        stroke.Enabled = false -- Default to no shadow

        if level > 0 then
            -- Simple shadow using UIStroke (can be improved)
            stroke.Enabled = true
            stroke.Color = MaterialTheme.getColor("shadow") or Color3.fromRGB(0,0,0)
            stroke.Thickness = level * 1 -- Increase thickness with level
            stroke.Transparency = 0.8 - (level * 0.1) -- Decrease transparency slightly

            -- For a softer shadow, you might use a 9-slice image or multiple transparent frames.
            -- Example using a simple dark frame offset:
            -- shadow.BackgroundColor3 = MaterialTheme.getColor("shadow") or Color3.fromRGB(0,0,0)
            -- shadow.BackgroundTransparency = 0.85 - (level * 0.05)
            -- shadow.Position = UDim2.new(0, level * 0.5, 0, level * 1)
            -- if element:FindFirstChildOfClass("UICorner") then
            --     StyleUtils.applyCornerRadius(shadow, element:FindFirstChildOfClass("UICorner").CornerRadius)
            -- end
        end
    end
}


-- ##################################################################################
-- STYLE UTILITIES
-- ##################################################################################
StyleUtils = {
    applyCornerRadius = function(instance, radiusOrName)
        local radius = type(radiusOrName) == "string" and Sizing.CornerRadius[radiusOrName] or radiusOrName
        if not radius then
            warn("Kavo M3 Sizing: CornerRadius '" .. tostring(radiusOrName) .. "' not found.")
            radius = Sizing.CornerRadius.None
        end
        
        local corner = instance:FindFirstChildWhichIsA("UICorner")
        if not corner then
            corner = Instance.new("UICorner")
            corner.Parent = instance
        end
        corner.CornerRadius = radius
        return corner
    end,

    applyPadding = function(instance, paddingOrName)
        local paddingValue = type(paddingOrName) == "string" and Sizing.Padding[paddingOrName] or paddingOrName
         if not paddingValue then
            warn("Kavo M3 Sizing: Padding '" .. tostring(paddingOrName) .. "' not found.")
            paddingValue = Sizing.Padding.None
        end

        local padding = instance:FindFirstChildWhichIsA("UIPadding")
        if not padding then
            padding = Instance.new("UIPadding")
            padding.Parent = instance
        end
        -- Assuming uniform padding for simplicity
        padding.PaddingTop = paddingValue
        padding.PaddingBottom = paddingValue
        padding.PaddingLeft = paddingValue
        padding.PaddingRight = paddingValue
        return padding
    end,

    applyTypography = function(textInstance, styleNameOrStyle)
        Typography.applyStyle(textInstance, styleNameOrStyle)
        if textInstance:IsA("TextLabel") or textInstance:IsA("TextButton") or textInstance:IsA("TextBox") then
            -- Default text color based on the parent's likely surface
            -- This is a heuristic. Ideally, components specify their "on" color.
            local parentSurfaceColor = textInstance.Parent and textInstance.Parent.BackgroundColor3
            if parentSurfaceColor == MaterialTheme.getColor("primary") then
                textInstance.TextColor3 = MaterialTheme.getColor("onPrimary")
            elseif parentSurfaceColor == MaterialTheme.getColor("secondary") then
                textInstance.TextColor3 = MaterialTheme.getColor("onSecondary")
            elseif parentSurfaceColor == MaterialTheme.getColor("tertiary") then
                textInstance.TextColor3 = MaterialTheme.getColor("onTertiary")
            elseif parentSurfaceColor == MaterialTheme.getColor("error") then
                textInstance.TextColor3 = MaterialTheme.getColor("onError")
            elseif parentSurfaceColor == MaterialTheme.getColor("surfaceContainerHighest") or
                   parentSurfaceColor == MaterialTheme.getColor("surfaceContainerHigh") or
                   parentSurfaceColor == MaterialTheme.getColor("surfaceContainer") or
                   parentSurfaceColor == MaterialTheme.getColor("surfaceContainerLow") or
                   parentSurfaceColor == MaterialTheme.getColor("surfaceContainerLowest") or
                   parentSurfaceColor == MaterialTheme.getColor("surface") then
                textInstance.TextColor3 = MaterialTheme.getColor("onSurface")
            else
                textInstance.TextColor3 = MaterialTheme.getColor("onSurface") -- Default fallback
            end
        end
    end,
    
    createInstance = function(className, properties)
        local instance = Instance.new(className)
        for prop, value in pairs(properties or {}) do
            if prop == "Typography" then
                StyleUtils.applyTypography(instance, value)
            elseif prop == "CornerRadius" then
                StyleUtils.applyCornerRadius(instance, value)
            elseif prop == "Padding" then
                StyleUtils.applyPadding(instance, value)
            elseif prop == "Children" and type(value) == "table" then
                for _, childProps in ipairs(value) do
                    local childClass = childProps.ClassName
                    childProps.ClassName = nil -- Remove it so it's not set as a property
                    childProps.Parent = instance -- Set parent
                    StyleUtils.createInstance(childClass, childProps) -- Recursive call
                end
            else
                if type(value) == "string" and MaterialTheme.CurrentScheme[value] and (prop == "BackgroundColor3" or prop == "TextColor3" or prop == "ImageColor3" or prop == "BorderColor3") then
                    instance[prop] = MaterialTheme.getColor(value)
                else
                    instance[prop] = value
                end
            end
        end
        return instance
    end,
}

-- ##################################################################################
-- RIPPLE EFFECT UTILITY (Material Design click feedback)
-- ##################################################################################
RippleEffectUtil = {
    createRipple = function(targetButton, clickPosition)
        if not targetButton or not targetButton:IsA("GuiButton") then return end

        local ripple = StyleUtils.createInstance("ImageLabel", {
            Name = "M3RippleEffect",
            Parent = targetButton,
            Size = UDim2.fromOffset(0, 0), -- Start small
            Position = UDim2.fromOffset(clickPosition.X, clickPosition.Y),
            AnchorPoint = Vector2.new(0.5, 0.5),
            BackgroundTransparency = 1,
            Image = "rbxassetid://2641510793", -- Circle image (or use a UICorner on a Frame)
            ImageColor3 = MaterialTheme.getColor("onSurface"), -- Or onPrimary, etc. based on button
            ImageTransparency = 0.7, -- Initial transparency
            ScaleType = Enum.ScaleType.Stretch,
            ZIndex = targetButton.ZIndex + 10, -- Ensure it's on top
            ClipsDescendants = true, -- Important if targetButton has UICorner
        })
        StyleUtils.applyCornerRadius(ripple, Sizing.CornerRadius.Full) -- Make it circular

        local targetSize = math.max(targetButton.AbsoluteSize.X, targetButton.AbsoluteSize.Y) * 1.5
        local tweenInfo = TweenInfo.new(0.4, Enum.EasingStyle.Linear)

        local sizeTween = TweenService:Create(ripple, tweenInfo, {
            Size = UDim2.fromOffset(targetSize, targetSize)
        })
        local fadeTween = TweenService:Create(ripple, tweenInfo, {
            ImageTransparency = 0.95
        })

        sizeTween:Play()
        fadeTween:Play()

        fadeTween.Completed:Connect(function()
            ripple:Destroy()
        end)
    end,

    -- Attach ripple effect to a button
    attachToButton = function(button)
        button.AutoButtonColor = false -- We handle visual feedback
        button.MouseButton1Click:Connect(function()
            local mouseLocation = UserInputService:GetMouseLocation()
            local relativePos = mouseLocation - button.AbsolutePosition
            RippleEffectUtil.createRipple(button, relativePos)
            -- The original callback for the button should still fire
        end)
    end
}


-- ##################################################################################
-- DEFAULT MATERIAL 3 COLOR SCHEMES
-- ##################################################################################
MaterialTheme.Schemes.BaseLight = {
    primary = Color3.fromRGB(103, 80, 164),
    onPrimary = Color3.fromRGB(255, 255, 255),
    primaryContainer = Color3.fromRGB(234, 221, 255),
    onPrimaryContainer = Color3.fromRGB(33, 0, 93),

    secondary = Color3.fromRGB(98, 91, 113),
    onSecondary = Color3.fromRGB(255, 255, 255),
    secondaryContainer = Color3.fromRGB(228, 222, 248),
    onSecondaryContainer = Color3.fromRGB(29, 25, 43),

    tertiary = Color3.fromRGB(125, 82, 96),
    onTertiary = Color3.fromRGB(255, 255, 255),
    tertiaryContainer = Color3.fromRGB(255, 216, 228),
    onTertiaryContainer = Color3.fromRGB(55, 11, 30),

    error = Color3.fromRGB(179, 38, 30),
    onError = Color3.fromRGB(255, 255, 255),
    errorContainer = Color3.fromRGB(249, 222, 220),
    onErrorContainer = Color3.fromRGB(65, 14, 11),

    background = Color3.fromRGB(255, 251, 254),
    onBackground = Color3.fromRGB(28, 27, 31),

    surface = Color3.fromRGB(255, 251, 254),
    onSurface = Color3.fromRGB(28, 27, 31),
    surfaceDim = Color3.fromRGB(221, 217, 222), -- New M3 role
    surfaceBright = Color3.fromRGB(255, 251, 254), -- New M3 role

    surfaceContainerLowest = Color3.fromRGB(255, 255, 255),
    surfaceContainerLow = Color3.fromRGB(247, 242, 248),
    surfaceContainer = Color3.fromRGB(241, 236, 242),
    surfaceContainerHigh = Color3.fromRGB(235, 230, 236),
    surfaceContainerHighest = Color3.fromRGB(229, 224, 230),

    onSurfaceVariant = Color3.fromRGB(73, 69, 79),
    outline = Color3.fromRGB(121, 116, 126),
    outlineVariant = Color3.fromRGB(202, 196, 208),

    shadow = Color3.fromRGB(0,0,0),
    scrim = Color3.fromRGB(0,0,0), -- For overlays, usually with transparency

    inverseSurface = Color3.fromRGB(49, 48, 51),
    onInverseSurface = Color3.fromRGB(244, 239, 244),
    inversePrimary = Color3.fromRGB(208, 188, 255),
    
    surfaceTint = Color3.fromRGB(103, 80, 164), -- Same as primary for tinting
}

MaterialTheme.Schemes.BaseDark = {
    primary = Color3.fromRGB(208, 188, 255),
    onPrimary = Color3.fromRGB(56, 30, 114),
    primaryContainer = Color3.fromRGB(79, 54, 139),
    onPrimaryContainer = Color3.fromRGB(234, 221, 255),

    secondary = Color3.fromRGB(204, 194, 220),
    onSecondary = Color3.fromRGB(50, 44, 66),
    secondaryContainer = Color3.fromRGB(74, 68, 90),
    onSecondaryContainer = Color3.fromRGB(232, 222, 248),

    tertiary = Color3.fromRGB(239, 184, 200),
    onTertiary = Color3.fromRGB(73, 37, 50),
    tertiaryContainer = Color3.fromRGB(99, 59, 72),
    onTertiaryContainer = Color3.fromRGB(255, 216, 228),

    error = Color3.fromRGB(242, 184, 181),
    onError = Color3.fromRGB(96, 20, 16),
    errorContainer = Color3.fromRGB(140, 29, 24),
    onErrorContainer = Color3.fromRGB(249, 222, 220),

    background = Color3.fromRGB(28, 27, 31),
    onBackground = Color3.fromRGB(229, 225, 229),

    surface = Color3.fromRGB(28, 27, 31),
    onSurface = Color3.fromRGB(229, 225, 229),
    surfaceDim = Color3.fromRGB(28, 27, 31), -- New M3 role
    surfaceBright = Color3.fromRGB(60, 58, 63), -- New M3 role

    surfaceContainerLowest = Color3.fromRGB(23, 22, 26),
    surfaceContainerLow = Color3.fromRGB(37, 35, 40),
    surfaceContainer = Color3.fromRGB(41, 39, 44),
    surfaceContainerHigh = Color3.fromRGB(52, 50, 55),
    surfaceContainerHighest = Color3.fromRGB(63, 60, 66),

    onSurfaceVariant = Color3.fromRGB(202, 196, 208),
    outline = Color3.fromRGB(147, 143, 153),
    outlineVariant = Color3.fromRGB(73, 69, 79),

    shadow = Color3.fromRGB(0,0,0),
    scrim = Color3.fromRGB(0,0,0),

    inverseSurface = Color3.fromRGB(229, 225, 229),
    onInverseSurface = Color3.fromRGB(49, 48, 51),
    inversePrimary = Color3.fromRGB(103, 80, 164),

    surfaceTint = Color3.fromRGB(208, 188, 255), -- Same as primary for tinting
}

-- Set a default theme
MaterialTheme.setTheme("BaseLight") -- Or "BaseDark"


-- ##################################################################################
-- KAVO CORE LIBRARY
-- ##################################################################################

local LibInstance = {
    RegisteredObjects = {}, -- For theme updates
    MainFrame = nil,
    PagesFolder = nil,
    TabFramesContainer = nil,
    CurrentThemeName = "BaseLight",
}

function LibInstance:UpdateTheme()
    if not self.MainFrame then return end
    
    local theme = MaterialTheme.CurrentScheme

    self.MainFrame.BackgroundColor3 = theme.surfaceContainerLow
    
    local header = self.MainFrame:FindFirstChild("MainHeader")
    if header then
        header.BackgroundColor3 = theme.surface -- Or surfaceContainer
        local title = header:FindFirstChild("Title")
        if title then title.TextColor3 = theme.onSurfaceVariant end
    end

    local sideBar = self.MainFrame:FindFirstChild("MainSide")
    if sideBar then
        sideBar.BackgroundColor3 = theme.surfaceContainer -- Or surfaceContainerLow
    end

    -- Update all registered objects
    for obj, props in pairs(self.RegisteredObjects) do
        if obj and obj.Parent then -- Check if object still exists
            if type(props) == "string" then -- Simple color role assignment
                if obj:IsA("Frame") or obj:IsA("ImageLabel") or obj:IsA("TextButton") then -- common background props
                    obj.BackgroundColor3 = MaterialTheme.getColor(props)
                elseif obj:IsA("TextLabel") or obj:IsA("TextBox") then -- common text color props
                     obj.TextColor3 = MaterialTheme.getColor(props)
                elseif obj:IsA("ImageButton") then
                    obj.ImageColor3 = MaterialTheme.getColor(props)
                end
            elseif type(props) == "table" then -- More complex styling
                for propName, colorRole in pairs(props) do
                    if obj[propName] then
                        obj[propName] = MaterialTheme.getColor(colorRole)
                    end
                end
            end
        else
            self.RegisteredObjects[obj] = nil -- Remove destroyed object
        end
    end
    
    -- Update tab buttons
    if self.TabFramesContainer then
        for _, tabButton in ipairs(self.TabFramesContainer:GetChildren()) do
            if tabButton:IsA("TextButton") and tabButton.Name:match("TabButton$") then
                if tabButton.Activated then -- Custom property to track active state
                    tabButton.BackgroundColor3 = theme.secondaryContainer
                    tabButton.TextColor3 = theme.onSecondaryContainer
                    if tabButton:FindFirstChild("Indicator") then
                        tabButton.Indicator.BackgroundColor3 = theme.primary
                    end
                else
                    tabButton.BackgroundColor3 = Color3.new(1,1,1) -- Fully transparent or specific inactive color
                    tabButton.BackgroundTransparency = 1
                    tabButton.TextColor3 = theme.onSurfaceVariant
                     if tabButton:FindFirstChild("Indicator") then
                        tabButton.Indicator.BackgroundColor3 = Color3.new(1,1,1)
                        tabButton.Indicator.BackgroundTransparency = 1
                    end
                end
            end
        end
    end

    -- Update pages
    if self.PagesFolder then
        for _, page in ipairs(self.PagesFolder:GetChildren()) do
            if page:IsA("ScrollingFrame") then
                page.BackgroundColor3 = theme.surfaceContainerLow
                page.ScrollBarImageColor3 = theme.outlineVariant
                -- Update sections within pages
                for _, sectionFrame in ipairs(page:GetChildren()) do
                    if sectionFrame.Name == "M3SectionFrame" then
                        sectionFrame.BackgroundColor3 = theme.surfaceContainerLow -- Sections are on the page background
                        local sectionHeader = sectionFrame:FindFirstChild("M3SectionHeader")
                        if sectionHeader then
                            sectionHeader.BackgroundColor3 = theme.surfaceContainer -- Slightly different from page
                            local sectionTitle = sectionHeader:FindFirstChild("M3SectionTitle")
                            if sectionTitle then sectionTitle.TextColor3 = theme.onSurfaceVariant end
                        end
                        local sectionContent = sectionFrame:FindFirstChild("M3SectionContent")
                        if sectionContent then
                            -- Elements within sectionContent will have their own styling rules
                        end
                    end
                end
            end
        end
    end

    print("Kavo M3: Theme updated to " .. self.CurrentThemeName)
end


function Kavo:DraggingEnabled(frame, parent)
    parent = parent or frame
    local dragging = false
    local dragInput, mousePos, framePos

    frame.InputBegan:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1 then
            dragging = true
            mousePos = input.Position
            framePos = parent.Position
            
            input.Changed:Connect(function()
                if input.UserInputState == Enum.UserInputState.End then
                    dragging = false
                end
            end)
        end
    end)

    frame.InputChanged:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseMovement then
            dragInput = input
        end
    end)

    UserInputService.InputChanged:Connect(function(input)
        if input == dragInput and dragging and parent and parent.Parent then -- Ensure parent is valid
            local delta = input.Position - mousePos
            parent.Position  = UDim2.new(framePos.X.Scale, framePos.X.Offset + delta.X, framePos.Y.Scale, framePos.Y.Offset + delta.Y)
        end
    end)
end

Kavo.ActiveLibInstance = LibInstance -- Allow access for theme updates

function Kavo.CreateLib(libName, themeChoice)
    libName = libName or "Kavo Library"
    themeChoice = themeChoice or "BaseLight" -- Default to BaseLight
    MaterialTheme.setTheme(themeChoice)
    LibInstance.CurrentThemeName = themeChoice

    -- Destroy previous instance if any
    local oldGui = CoreGui:FindFirstChild("KavoM3ScreenGui")
    if oldGui then oldGui:Destroy() end

    local screenGui = StyleUtils.createInstance("ScreenGui", {
        Name = "KavoM3ScreenGui",
        Parent = CoreGui,
        ZIndexBehavior = Enum.ZIndexBehavior.Sibling,
        ResetOnSpawn = false,
    })

    LibInstance.MainFrame = StyleUtils.createInstance("Frame", {
        Name = "MainFrame",
        Parent = screenGui,
        Size = UDim2.new(0, 600, 0, 400), -- Example Size
        Position = UDim2.new(0.5, -300, 0.5, -200), -- Centered
        BackgroundColor3 = MaterialTheme.getColor("surfaceContainerLow"),
        ClipsDescendants = true,
        CornerRadius = Sizing.CornerRadius.Large, -- Dialog-like rounding
        Children = {
            { ClassName = "UIPadding", Padding = Sizing.Padding.None }, -- No padding on mainframe itself
        }
    })
    -- Apply elevation to the main dialog/frame
    Elevation.applyShadow(LibInstance.MainFrame, 3) -- Level 3 elevation for dialogs
    MaterialTheme.applySurfaceTint(LibInstance.MainFrame, MaterialTheme.getColor("surfaceTint"), 3)


    local mainHeader = StyleUtils.createInstance("Frame", {
        Name = "MainHeader",
        Parent = LibInstance.MainFrame,
        Size = UDim2.new(1, 0, 0, 56), -- M3 Top App Bar height
        BackgroundColor3 = MaterialTheme.getColor("surface"), -- Or surfaceContainer
        ClipsDescendants = true, -- Important for top corners if main frame is rounded
        Children = {
            { ClassName = "UICorner", CornerRadius = UDim.new(Sizing.CornerRadius.Large.Offset,0) }, -- Match top corners
            { ClassName = "UIPadding", PaddingLeft = Sizing.Padding.Large, PaddingRight = Sizing.Padding.Small },
            {
                ClassName = "TextLabel", Name = "Title",
                Text = libName,
                Typography = "TitleLarge", TextColor3 = "onSurfaceVariant",
                Size = UDim2.new(1, -60, 1, 0), -- Leave space for close button
                TextXAlignment = Enum.TextXAlignment.Left,
                BackgroundTransparency = 1,
            },
            {
                ClassName = "ImageButton", Name = "CloseButton",
                Size = UDim2.fromOffset(40, 40),
                Position = UDim2.new(1, -48, 0.5, -20), AnchorPoint = Vector2.new(0,0.5),
                BackgroundTransparency = 1,
                Image = "rbxassetid://3926305904", -- Close icon
                ImageRectOffset = Vector2.new(284, 4), ImageRectSize = Vector2.new(24, 24),
                ImageColor3 = "onSurfaceVariant",
            }
        }
    })
    -- Manually set top corners for header to only round top-left and top-right
    local headerCorner = mainHeader:FindFirstChildOfClass("UICorner")
    -- This direct manipulation of individual corners isn't possible with UICorner.
    -- Instead, the MainFrame ClipsDescendants will handle the visual rounding.
    -- If specific corner rounding is needed, 9-slice or multiple frames are required.

    local closeButton = mainHeader:FindFirstChild("CloseButton")
    RippleEffectUtil.attachToButton(closeButton) -- Add ripple
    closeButton.MouseButton1Click:Connect(function()
        -- Add fade out animation if desired
        screenGui:Destroy()
        Kavo.ActiveLibInstance.MainFrame = nil -- Clear reference
    end)
    
    Kavo:DraggingEnabled(mainHeader, LibInstance.MainFrame)

    -- Main content area (sidebar and pages)
    local contentArea = StyleUtils.createInstance("Frame", {
        Name = "ContentArea",
        Parent = LibInstance.MainFrame,
        Size = UDim2.new(1, 0, 1, -mainHeader.AbsoluteSize.Y), -- Fill remaining space
        Position = UDim2.new(0, 0, 0, mainHeader.AbsoluteSize.Y),
        BackgroundTransparency = 1,
        Layout = "UIListLayout", -- Horizontal layout for SideBar + PagesContainer
        Children = {
            { ClassName = "UIListLayout", FillDirection = Enum.FillDirection.Horizontal, Padding = Sizing.Padding.None}
        }
    })
    local contentLayout = contentArea:FindFirstChildOfClass("UIListLayout")


    -- Sidebar for Tabs
    local mainSide = StyleUtils.createInstance("Frame", {
        Name = "MainSide",
        Parent = contentArea, -- Parent is now contentArea
        Size = UDim2.new(0, 200, 1, 0), -- Example width, full height of contentArea
        BackgroundColor3 = MaterialTheme.getColor("surfaceContainer"),
        Children = {
            { ClassName = "UIPadding", Padding = Sizing.Padding.Small },
            { ClassName = "UIListLayout", FillDirection = Enum.FillDirection.Vertical, Padding = Sizing.Padding.Small, SortOrder = Enum.SortOrder.LayoutOrder }
        }
    })
    LibInstance.TabFramesContainer = mainSide -- Store reference to the tab container

    -- Pages Container
    local pagesContainer = StyleUtils.createInstance("Frame", {
        Name = "PagesContainer",
        Parent = contentArea, -- Parent is now contentArea
        Size = UDim2.new(1, -mainSide.AbsoluteSize.X, 1, 0), -- Fill remaining width
        BackgroundTransparency = 1, -- Pages will have their own background
        ClipsDescendants = true,
    })
    
    LibInstance.PagesFolder = StyleUtils.createInstance("Folder", { Name = "Pages", Parent = pagesContainer })

    -- Initialize the theme for the newly created elements
    LibInstance:UpdateTheme() -- Call initial theme update

    local Tabs = {}
    local firstTab = true

    function Tabs:NewTab(tabName)
        tabName = tabName or "Tab"
        
        local page = StyleUtils.createInstance("ScrollingFrame", {
            Name = tabName .. "Page",
            Parent = LibInstance.PagesFolder,
            Size = UDim2.new(1,0,1,0),
            BackgroundColor3 = MaterialTheme.getColor("surfaceContainerLow"),
            BorderSizePixel = 0,
            ScrollBarThickness = 8,
            ScrollBarImageColor3 = MaterialTheme.getColor("outlineVariant"),
            Visible = false, -- Initially hidden
            CanvasSize = UDim2.new(0,0,0,0), -- Will be updated by content
            Children = {
                { ClassName = "UIListLayout", Padding = Sizing.Padding.Medium, SortOrder = Enum.SortOrder.LayoutOrder, HorizontalAlignment = Enum.HorizontalAlignment.Center },
                { ClassName = "UIPadding", Padding = Sizing.Padding.Large } -- Padding for content within the page
            }
        })
        local pageListLayout = page:FindFirstChildOfClass("UIListLayout")

        local tabButton = StyleUtils.createInstance("TextButton", {
            Name = tabName .. "TabButton",
            Parent = LibInstance.TabFramesContainer,
            Size = UDim2.new(1, 0, 0, Sizing.ElementHeight.ListItem), -- M3 list item height
            Text = tabName,
            Typography = "LabelLarge",
            BackgroundColor3 = Color3.new(1,1,1), BackgroundTransparency = 1, -- Initially transparent
            TextColor3 = MaterialTheme.getColor("onSurfaceVariant"),
            CornerRadius = Sizing.CornerRadius.Full, -- Pill shape for tabs
            Children = {
                { ClassName = "UIPadding", PaddingLeft = Sizing.Padding.Medium, PaddingRight = Sizing.Padding.Medium },
                { ClassName = "Frame", Name = "Indicator", -- Active indicator (optional, M3 often uses background change)
                  Size = UDim2.new(0,4,0,24), Position = UDim2.new(0,0,0.5,-12), AnchorPoint = Vector2.new(0,0.5),
                  BackgroundColor3 = MaterialTheme.getColor("primary"), BackgroundTransparency = 1,
                  CornerRadius = Sizing.CornerRadius.Full,
                }
            }
        })
        RippleEffectUtil.attachToButton(tabButton)

        local function updatePageCanvasSize()
            RunService.Heartbeat:Wait() -- Wait a frame for layout to compute
            local contentHeight = pageListLayout.AbsoluteContentSize.Y
            page.CanvasSize = UDim2.new(0, 0, 0, contentHeight)
        end
        page.ChildAdded:Connect(updatePageCanvasSize)
        page.ChildRemoved:Connect(updatePageCanvasSize)


        tabButton.MouseButton1Click:Connect(function()
            for _, otherPage in ipairs(LibInstance.PagesFolder:GetChildren()) do
                if otherPage:IsA("ScrollingFrame") then otherPage.Visible = false end
            end
            page.Visible = true

            for _, otherTabButton in ipairs(LibInstance.TabFramesContainer:GetChildren()) do
                if otherTabButton:IsA("TextButton") and otherTabButton.Name:match("TabButton$") then
                    otherTabButton.BackgroundColor3 = Color3.new(1,1,1) -- Transparent
                    otherTabButton.BackgroundTransparency = 1
                    otherTabButton.TextColor3 = MaterialTheme.getColor("onSurfaceVariant")
                    otherTabButton.Activated = false
                    if otherTabButton:FindFirstChild("Indicator") then otherTabButton.Indicator.BackgroundTransparency = 1 end
                end
            end
            tabButton.BackgroundColor3 = MaterialTheme.getColor("secondaryContainer")
            tabButton.BackgroundTransparency = 0
            tabButton.TextColor3 = MaterialTheme.getColor("onSecondaryContainer")
            tabButton.Activated = true
             if tabButton:FindFirstChild("Indicator") then tabButton.Indicator.BackgroundTransparency = 0 end
            updatePageCanvasSize()
        end)

        if firstTab then
            tabButton:Activated() -- Click the first tab
            firstTab = false
        end

        local Sections = {}
        function Sections:NewSection(sectionTitleText, isHidden)
            sectionTitleText = sectionTitleText or "Section"
            
            local sectionFrame = StyleUtils.createInstance("Frame", {
                Name = "M3SectionFrame",
                Parent = page, -- Parent is the tab's page
                AutomaticSize = Enum.AutomaticSize.Y, -- Auto size based on content
                Size = UDim2.new(1, -Sizing.Padding.Large.Offset*2, 0, 0), -- Full width minus page padding
                BackgroundColor3 = MaterialTheme.getColor("surfaceContainerLow"), -- Should match page background
                Children = {
                    { ClassName = "UIListLayout", FillDirection = Enum.FillDirection.Vertical, Padding = Sizing.Padding.Small}
                }
            })

            if not isHidden then
                local sectionHeader = StyleUtils.createInstance("Frame", {
                    Name = "M3SectionHeader",
                    Parent = sectionFrame,
                    Size = UDim2.new(1, 0, 0, Sizing.ElementHeight.ListItem),
                    BackgroundTransparency = 1, -- Header is just for the title text usually
                    Children = {
                        { ClassName = "UIPadding", PaddingLeft = Sizing.Padding.Medium, PaddingRight = Sizing.Padding.Medium },
                        {
                            ClassName = "TextLabel", Name = "M3SectionTitle",
                            Text = sectionTitleText,
                            Typography = "TitleSmall", TextColor3 = "onSurfaceVariant",
                            Size = UDim2.new(1,0,1,0), TextXAlignment = Enum.TextXAlignment.Left,
                            BackgroundTransparency = 1,
                        }
                    }
                })
            end

            local sectionContent = StyleUtils.createInstance("Frame", {
                Name = "M3SectionContent",
                Parent = sectionFrame,
                AutomaticSize = Enum.AutomaticSize.Y,
                Size = UDim2.new(1,0,0,0),
                BackgroundTransparency = 1,
                Children = {
                    { ClassName = "UIListLayout", FillDirection = Enum.FillDirection.Vertical, Padding = Sizing.Padding.Medium },
                    { ClassName = "UIPadding", Padding = Sizing.Padding.None } -- Elements will have their own internal padding
                }
            })
            
            local Elements = {}
            function Elements:NewButton(buttonText, tipText, callback)
                buttonText = buttonText or "Button"
                callback = callback or function() print(buttonText .. " clicked") end
                
                -- Example: Filled Button
                local button = StyleUtils.createInstance("TextButton", {
                    Name = buttonText .. "Button",
                    Parent = sectionContent, -- Add to section's content area
                    Size = UDim2.new(1, 0, 0, Sizing.ElementHeight.Button),
                    Text = buttonText,
                    BackgroundColor3 = "primary", -- Use color role name
                    TextColor3 = "onPrimary",
                    Typography = "LabelLarge",
                    CornerRadius = Sizing.CornerRadius.Full, -- Pill shape for buttons
                })
                RippleEffectUtil.attachToButton(button)
                button.MouseButton1Click:Connect(callback)

                -- Register for theme updates (example, could be more granular)
                LibInstance.RegisteredObjects[button] = { BackgroundColor3 = "primary", TextColor3 = "onPrimary" }
                
                updatePageCanvasSize() -- Update canvas after adding an element
                return button -- Return the instance for further manipulation if needed
            end
            
            function Elements:NewLabel(labelText, styleName)
                labelText = labelText or "Label"
                styleName = styleName or "BodyMedium"

                local label = StyleUtils.createInstance("TextLabel", {
                    Name = labelText .. "Label",
                    Parent = sectionContent,
                    Text = labelText,
                    Size = UDim2.new(1,0,0,0), -- Auto height based on text
                    AutomaticSize = Enum.AutomaticSize.Y,
                    BackgroundTransparency = 1,
                    TextColor3 = "onSurface",
                    Typography = styleName,
                    TextWrapped = true,
                    TextXAlignment = Enum.TextXAlignment.Left,
                })
                LibInstance.RegisteredObjects[label] = { TextColor3 = "onSurface" }
                updatePageCanvasSize()
                return label
            end

            -- TODO: Add NewTextBox, NewToggle, NewSlider, NewDropdown, NewKeybind, NewColorPicker
            -- Each would use StyleUtils.createInstance and apply Material 3 theming.
            -- Example: NewTextBox
            function Elements:NewTextBox(placeholderText, tipText, callback)
                placeholderText = placeholderText or "Type here..."
                callback = callback or function(text) print("TextBox submitted:", text) end

                local M3TextFieldHeight = Sizing.ElementHeight.TextField

                local container = StyleUtils.createInstance("Frame", {
                    Name = "M3TextFieldContainer",
                    Parent = sectionContent,
                    Size = UDim2.new(1,0,0, M3TextFieldHeight + 16), -- Extra space for label/helper if any
                    BackgroundTransparency = 1,
                    Children = {
                        {ClassName = "UIListLayout", FillDirection = Enum.FillDirection.Vertical, Padding = Sizing.Padding.ExtraSmall}
                    }
                })
                
                -- Optional Label (M3 often has labels above the field)
                local label = StyleUtils.createInstance("TextLabel", {
                    Name = "FieldLabel", Parent = container,
                    Text = tipText or "", Typography = "BodySmall", TextColor3 = "onSurfaceVariant",
                    Size = UDim2.new(1,0,0,16), BackgroundTransparency = 1, Visible = tipText ~= nil,
                    TextXAlignment = Enum.TextXAlignment.Left,
                })


                local textBoxFrame = StyleUtils.createInstance("Frame", {
                    Name = "TextBoxFrame",
                    Parent = container,
                    Size = UDim2.new(1, 0, 0, M3TextFieldHeight),
                    BackgroundColor3 = "surfaceContainerHighest", -- Or surfaceVariant
                    CornerRadius = Sizing.CornerRadius.ExtraSmall, -- M3 TextFields have small top rounding
                    ClipsDescendants = true,
                    Children = {
                        {ClassName = "UIStroke", Color = MaterialTheme.getColor("outline"), Thickness = 1, ApplyStrokeMode = Enum.ApplyStrokeMode.Border, Name = "OutlineStroke"},
                        {ClassName = "UIPadding", PaddingLeft = Sizing.Padding.Medium, PaddingRight = Sizing.Padding.Medium},
                    }
                })
                LibInstance.RegisteredObjects[textBoxFrame] = { BackgroundColor3 = "surfaceContainerHighest" }
                LibInstance.RegisteredObjects[textBoxFrame.OutlineStroke] = { Color = "outline" }


                local textBox = StyleUtils.createInstance("TextBox", {
                    Name = "InputTextBox",
                    Parent = textBoxFrame,
                    Size = UDim2.new(1, 0, 1, 0),
                    PlaceholderText = placeholderText,
                    PlaceholderColor3 = MaterialTheme.getColor("onSurfaceVariant"),
                    Text = "",
                    TextColor3 = "onSurface",
                    Typography = "BodyLarge",
                    BackgroundTransparency = 1,
                    ClearTextOnFocus = false,
                    TextXAlignment = Enum.TextXAlignment.Left,
                })
                LibInstance.RegisteredObjects[textBox] = { TextColor3 = "onSurface", PlaceholderColor3 = "onSurfaceVariant" }

                textBox.FocusLost:Connect(function(enterPressed)
                    textBoxFrame.OutlineStroke.Color = MaterialTheme.getColor("outline")
                    textBoxFrame.OutlineStroke.Thickness = 1
                    if enterPressed then
                        callback(textBox.Text)
                    end
                end)

                textBox.Focused:Connect(function()
                    textBoxFrame.OutlineStroke.Color = MaterialTheme.getColor("primary")
                    textBoxFrame.OutlineStroke.Thickness = 2
                end)
                
                updatePageCanvasSize()
                return textBox
            end


            updatePageCanvasSize()
            return Elements
        end
        return Sections
    end
    return Tabs
end

return Kavo
