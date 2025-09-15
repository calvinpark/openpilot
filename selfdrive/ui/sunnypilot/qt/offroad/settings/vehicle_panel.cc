/**
 * Copyright (c) 2021-, Haibin Wen, sunnypilot, and a number of other contributors.
 *
 * This file is part of sunnypilot and is licensed under the MIT License.
 * See the LICENSE.md file in the root directory for more details.
 */

#include "selfdrive/ui/sunnypilot/qt/offroad/settings/vehicle_panel.h"

#include <QLabel>
#include <QStackedWidget>
#include "selfdrive/ui/qt/widgets/input.h"
#include "selfdrive/ui/sunnypilot/qt/offroad/settings/vehicle/brand_settings_factory.h"
#include "selfdrive/ui/sunnypilot/qt/offroad/settings/vehicle/brands.h"
#include "selfdrive/ui/sunnypilot/qt/widgets/scrollview.h"

VehiclePanel::VehiclePanel(QWidget *parent) : QFrame(parent) {
  main_layout = new QStackedLayout();
  setLayout(main_layout);

  // Create main screen with original Vehicle panel structure
  mainScreen = new QWidget();
  QVBoxLayout *screen_layout = new QVBoxLayout(mainScreen);
  screen_layout->setContentsMargins(50, 20, 50, 20);

  ListWidget *list = new ListWidget(mainScreen);

  platformSelector = new PlatformSelector();
  QObject::connect(platformSelector, &PlatformSelector::refreshPanel, this, &VehiclePanel::updateBrandSettings);
  list->addItem(platformSelector);

  brandSettingsContainer = new QWidget(mainScreen);
  brandSettingsContainerLayout = new QVBoxLayout(brandSettingsContainer);
  brandSettingsContainerLayout->setContentsMargins(0, 0, 0, 0);
  brandSettingsContainerLayout->setSpacing(0);
  list->addItem(brandSettingsContainer);

  // Toyota Security Key Manager button
  toyotaSecurityKeyBtn = new ButtonControlSP(tr("Toyota Security Key Manager"), tr("ENTER"), tr("Manage Toyota security keys."));

  // Initialize Toyota Security Key Manager settings
  toyotaSecuritySettings = new ToyotaSecurityKeyManagerSettings();

  QObject::connect(toyotaSecurityKeyBtn, &ButtonControlSP::clicked, [=]() {
    mainScroller->setLastScrollPosition();
    main_layout->setCurrentWidget(toyotaSecuritySettings);
  });

  QObject::connect(toyotaSecuritySettings, &ToyotaSecurityKeyManagerSettings::backPress, [=]() {
    mainScroller->restoreScrollPosition();
    main_layout->setCurrentWidget(mainScreen);
    updatePanel(offroad); // Refresh the entire Vehicle panel
    updateBrandSettings(); // Ensure brand settings are refreshed
  });

  list->addItem(toyotaSecurityKeyBtn);

  mainScroller = new ScrollViewSP(list, mainScreen);
  screen_layout->addWidget(mainScroller);

  main_layout->addWidget(mainScreen);
  main_layout->addWidget(toyotaSecuritySettings);
  main_layout->setCurrentWidget(mainScreen);

  currentBrandSettings = nullptr;

  QObject::connect(uiState(), &UIState::offroadTransition, this, &VehiclePanel::updatePanel);
}

void VehiclePanel::showEvent(QShowEvent *event) {
  updatePanel(offroad);
}

void VehiclePanel::updatePanel(bool _offroad) {
  offroad = _offroad;
  platformSelector->refresh(_offroad);
  updateBrandSettings();
}

void VehiclePanel::updateBrandSettings() {
  if (!isVisible()) {
    return;
  }

  if (currentBrandSettings) {
    brandSettingsContainerLayout->removeWidget(currentBrandSettings);
    delete currentBrandSettings;
    currentBrandSettings = nullptr;
  }

  if (BrandSettingsFactory::isBrandSupported(platformSelector->brand)) {
    currentBrandSettings = BrandSettingsFactory::createBrandSettings(platformSelector->brand, this);
    if (currentBrandSettings) {
      currentBrandSettings->setContentsMargins(0, 0, 0, 0);
      brandSettingsContainerLayout->addWidget(currentBrandSettings);
      currentBrandSettings->updatePanel(offroad);
    }
  }

  // Update Toyota Security Key Manager button visibility
  if (toyotaSecurityKeyBtn) {
    toyotaSecurityKeyBtn->setVisible(shouldShowToyotaSecurityKeyManager());
  }
}

bool VehiclePanel::shouldShowToyotaSecurityKeyManager() {
  // Check if the current platform is Toyota Sienna 4th gen
  // TODO: Add other Toyota models as needed
  return platformSelector && (platformSelector->platform == "TOYOTA_SIENNA_4TH_GEN" ||
                              platformSelector->platform.contains("SIENNA") ||
                              platformSelector->platform.contains("sienna"));
}
