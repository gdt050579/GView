#include "GView.hpp"

using namespace GView;

FileCache::FileCache()
{
    this->fileObj = nullptr;
}
FileCache::~FileCache()
{
    if (this->fileObj)
        delete this->fileObj;
    this->fileObj = nullptr;
}