#pragma once

#include "IDrop.hpp"

using namespace GView::Utils;

namespace GView::GenericPlugins::Droppper
{
ArtefactType IdentifyArtefact(DataCache& cache, Subcategory subcategory, uint64 start, uint64 end, Result result);

class ArtefactsUI : public Window
{
  private:
    std::vector<Buffer> entries;
    Reference<ListView> lv;

  public:
    ArtefactsUI(DataCache& cache, const std::vector<Finding>& findings);
};
} // namespace GView::GenericPlugins::Droppper