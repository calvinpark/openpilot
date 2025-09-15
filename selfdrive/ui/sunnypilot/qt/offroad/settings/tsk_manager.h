/*
 * Copyright (c) The sunnypilot contributors
 *
 * This file is part of sunnypilot.
 *
 */

#pragma once

#include <QWidget>
#include <QVBoxLayout>
#include "selfdrive/ui/sunnypilot/qt/widgets/controls.h"

class ToyotaSecurityKeyManagerSettings : public QWidget {
  Q_OBJECT

public:
  explicit ToyotaSecurityKeyManagerSettings(QWidget *parent = nullptr);

signals:
  void backPress();

private:
  ButtonControlSP* stubBtn1;
  ButtonControlSP* stubBtn2;
  ButtonControlSP* stubBtn3;
};
