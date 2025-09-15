/*
 * Copyright (c) The sunnypilot contributors
 *
 * This file is part of sunnypilot.
 *
 */

#include "selfdrive/ui/sunnypilot/qt/offroad/settings/tsk_manager.h"

#include <QLabel>
#include "selfdrive/ui/sunnypilot/qt/widgets/controls.h"
#include "selfdrive/ui/sunnypilot/qt/widgets/scrollview.h"

ToyotaSecurityKeyManagerSettings::ToyotaSecurityKeyManagerSettings(QWidget *parent) : QWidget(parent) {
  QVBoxLayout* main_layout = new QVBoxLayout(this);
  main_layout->setContentsMargins(20, 20, 20, 20);
  main_layout->setSpacing(20);

  // Back button with proper styling
  PanelBackButton* back = new PanelBackButton(tr("Back"));
  back->setStyleSheet(R"(
    #back_btn {
      font-size: 50px;
      margin: 0px;
      padding: 15px;
      border-width: 0;
      border-radius: 30px;
      color: #dddddd;
      background-color: #393939;
    }
    #back_btn:pressed {
      background-color: #4a4a4a;
    }
  )");
  connect(back, &QPushButton::clicked, [=]() { emit backPress(); });
  main_layout->addWidget(back, 0, Qt::AlignLeft);

  ListWidgetSP *list = new ListWidgetSP(this, false);

  // Stub menu items following the same pattern as lane change settings
  stubBtn1 = new ButtonControlSP(tr("Key Registration"), tr("ENTER"), tr("Add and configure new Toyota security keys for your vehicle."));
  QObject::connect(stubBtn1, &ButtonControlSP::clicked, [=]() {
    ConfirmationDialog("Key Registration - Coming Soon!", tr("OK"), "", false, this).exec();
  });
  list->addItem(stubBtn1);

  list->addItem(vertical_space());
  list->addItem(horizontal_line());
  list->addItem(vertical_space());

  stubBtn2 = new ButtonControlSP(tr("Key Management"), tr("ENTER"), tr("View, edit, or remove existing Toyota security keys."));
  QObject::connect(stubBtn2, &ButtonControlSP::clicked, [=]() {
    ConfirmationDialog("Key Management - Coming Soon!", tr("OK"), "", false, this).exec();
  });
  list->addItem(stubBtn2);

  list->addItem(vertical_space());
  list->addItem(horizontal_line());
  list->addItem(vertical_space());

  stubBtn3 = new ButtonControlSP(tr("Security Settings"), tr("ENTER"), tr("Adjust security preferences and authentication settings."));
  QObject::connect(stubBtn3, &ButtonControlSP::clicked, [=]() {
    ConfirmationDialog("Security Settings - Coming Soon!", tr("OK"), "", false, this).exec();
  });
  list->addItem(stubBtn3);

  main_layout->addWidget(new ScrollViewSP(list, this));
}
